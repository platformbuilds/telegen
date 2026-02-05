// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/platformbuilds/telegen/internal/ebpf/common"

import (
	"errors"
	"strings"
	"unsafe"

	"github.com/hashicorp/golang-lru/v2/simplelru"

	"github.com/platformbuilds/telegen/internal/appolly/app/request"
	"github.com/platformbuilds/telegen/internal/parsers/kafkaparser"
)

type Operation int8

const (
	Produce Operation = 0
	Fetch   Operation = 1
)

type PartitionInfo struct {
	Partition int
	Offset    int64
}

// TopicInfo holds information about a single Kafka topic in a request
type TopicInfo struct {
	Name          string
	PartitionInfo *PartitionInfo
}

type KafkaInfo struct {
	Operation     Operation
	Topic         string      // Primary topic (first topic, for backwards compatibility)
	Topics        []TopicInfo // All topics in the request
	ClientID      string
	PartitionInfo *PartitionInfo // Partition info for primary topic
}

func (k Operation) String() string {
	switch k {
	case Produce:
		return request.MessagingPublish
	case Fetch:
		return request.MessagingProcess
	default:
		return "unknown"
	}
}

// ProcessPossibleKafkaEvent processes a TCP packet and returns error if the packet is not a valid Kafka request.
// Otherwise, return kafka.Info with the processed data.
func ProcessPossibleKafkaEvent(event *TCPRequestInfo, pkt []byte, rpkt []byte, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (*KafkaInfo, bool, error) {
	k, ok, err := ProcessKafkaEvent(pkt, rpkt, kafkaTopicUUIDToName)
	if err != nil {
		// If we are getting the information in the response buffer, the event
		// must be reversed and that's how we captured it.
		k, ok, err = ProcessKafkaEvent(rpkt, pkt, kafkaTopicUUIDToName)
		if err == nil {
			reverseTCPEvent(event)
		}
	}
	return k, ok, err
}

func ProcessKafkaEvent(pkt []byte, rpkt []byte, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (*KafkaInfo, bool, error) {
	hdr, offset, err := kafkaparser.ParseKafkaRequestHeader(pkt)
	if err != nil {
		return nil, true, err
	}
	switch hdr.APIKey {
	case kafkaparser.APIKeyProduce:
		return processProduceRequest(pkt, hdr, offset)
	case kafkaparser.APIKeyFetch:
		return processFetchRequest(pkt, hdr, offset, kafkaTopicUUIDToName)
	case kafkaparser.APIKeyMetadata:
		return processMetadataResponse(rpkt, hdr, kafkaTopicUUIDToName)
	default:
		return nil, true, errors.New("unsupported Kafka API key")
	}
}

func processProduceRequest(pkt []byte, hdr *kafkaparser.KafkaRequestHeader, offset kafkaparser.Offset) (*KafkaInfo, bool, error) {
	produceReq, err := kafkaparser.ParseProduceRequest(pkt, hdr, offset)
	if err != nil {
		return nil, true, err
	}

	// Build topic info for all topics
	topics := make([]TopicInfo, 0, len(produceReq.Topics))
	for _, t := range produceReq.Topics {
		ti := TopicInfo{Name: t.Name}
		if t.Partition != nil {
			ti.PartitionInfo = &PartitionInfo{Partition: *t.Partition}
		}
		topics = append(topics, ti)
	}

	// Primary topic info (first topic for backwards compatibility)
	var partitionInfo *PartitionInfo
	primaryTopic := ""
	if len(topics) > 0 {
		primaryTopic = topics[0].Name
		partitionInfo = topics[0].PartitionInfo
	}

	return &KafkaInfo{
		ClientID:      hdr.ClientID,
		Operation:     Produce,
		Topic:         primaryTopic,
		Topics:        topics,
		PartitionInfo: partitionInfo,
	}, false, nil
}

func processFetchRequest(pkt []byte, hdr *kafkaparser.KafkaRequestHeader, offset kafkaparser.Offset, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (*KafkaInfo, bool, error) {
	fetchReq, err := kafkaparser.ParseFetchRequest(pkt, hdr, offset)
	if err != nil {
		return nil, true, err
	}

	// Build topic info for all topics
	topics := make([]TopicInfo, 0, len(fetchReq.Topics))
	for _, t := range fetchReq.Topics {
		topicName := t.Name
		// get topic name from UUID if available
		if t.UUID != nil {
			if name, found := kafkaTopicUUIDToName.Get(*t.UUID); found {
				topicName = name
			} else {
				topicName = "*"
			}
		}

		ti := TopicInfo{Name: topicName}
		if t.Partition != nil {
			ti.PartitionInfo = &PartitionInfo{
				Partition: t.Partition.Partition,
				Offset:    t.Partition.FetchOffset,
			}
		}
		topics = append(topics, ti)
	}

	// Primary topic info (first topic for backwards compatibility)
	var partitionInfo *PartitionInfo
	primaryTopic := ""
	if len(topics) > 0 {
		primaryTopic = topics[0].Name
		partitionInfo = topics[0].PartitionInfo
	}

	return &KafkaInfo{
		ClientID:      hdr.ClientID,
		Operation:     Fetch,
		Topic:         primaryTopic,
		Topics:        topics,
		PartitionInfo: partitionInfo,
	}, false, nil
}

func processMetadataResponse(rpkt []byte, hdr *kafkaparser.KafkaRequestHeader, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (*KafkaInfo, bool, error) {
	// only interested in response
	_, offset, err := kafkaparser.ParseKafkaResponseHeader(rpkt, hdr)
	if err != nil {
		return nil, true, err
	}
	metadataResponse, err := kafkaparser.ParseMetadataResponse(rpkt, hdr, offset)
	if err != nil {
		return nil, true, err
	}
	for _, topic := range metadataResponse.Topics {
		kafkaTopicUUIDToName.Add(topic.UUID, topic.Name)
	}
	return nil, true, nil
}

func ProcessKafkaRequest(pkt []byte, kafkaTopicUUIDToName *simplelru.LRU[kafkaparser.UUID, string]) (*KafkaInfo, bool, error) {
	hdr, offset, err := kafkaparser.ParseKafkaRequestHeader(pkt)
	if err != nil {
		return nil, true, err
	}
	switch hdr.APIKey {
	case kafkaparser.APIKeyProduce:
		return processProduceRequest(pkt, hdr, offset)
	case kafkaparser.APIKeyFetch:
		return processFetchRequest(pkt, hdr, offset, kafkaTopicUUIDToName)
	default:
		return nil, true, errors.New("unsupported Kafka API key")
	}
}

func TCPToKafkaToSpan(trace *TCPRequestInfo, data *KafkaInfo) request.Span {
	peer := ""
	hostname := ""
	hostPort := 0

	if trace.ConnInfo.S_port != 0 || trace.ConnInfo.D_port != 0 {
		peer, hostname = (*BPFConnInfo)(unsafe.Pointer(&trace.ConnInfo)).reqHostInfo()
		hostPort = int(trace.ConnInfo.D_port)
	}

	reqType := request.EventTypeKafkaClient
	if trace.Direction == 0 {
		reqType = request.EventTypeKafkaServer
	}

	var messagingInfo *request.MessagingInfo

	if data.PartitionInfo != nil {
		messagingInfo = &request.MessagingInfo{
			Partition: data.PartitionInfo.Partition,
			Offset:    data.PartitionInfo.Offset,
		}
	}

	// Build topic path - join multiple topics with comma if present
	topicPath := data.Topic
	if len(data.Topics) > 1 {
		topicNames := make([]string, 0, len(data.Topics))
		for _, t := range data.Topics {
			topicNames = append(topicNames, t.Name)
		}
		topicPath = strings.Join(topicNames, ",")
	}

	return request.Span{
		Type:          reqType,
		Method:        data.Operation.String(),
		Statement:     data.ClientID,
		Path:          topicPath,
		Peer:          peer,
		PeerPort:      int(trace.ConnInfo.S_port),
		Host:          hostname,
		HostPort:      hostPort,
		ContentLength: 0,
		RequestStart:  int64(trace.StartMonotimeNs),
		Start:         int64(trace.StartMonotimeNs),
		End:           int64(trace.EndMonotimeNs),
		Status:        0,
		TraceID:       trace.Tp.TraceId,
		SpanID:        trace.Tp.SpanId,
		ParentSpanID:  trace.Tp.ParentId,
		TraceFlags:    trace.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   trace.Pid.HostPid,
			UserPID:   trace.Pid.UserPid,
			Namespace: trace.Pid.Ns,
		},
		MessagingInfo: messagingInfo,
	}
}
