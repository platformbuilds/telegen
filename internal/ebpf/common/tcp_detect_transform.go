// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"errors"
	"fmt"
	"log/slog"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/obiconfig"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/kafkaparser"
	"github.com/mirastacklabs-ai/telegen/internal/ringbuf"
)

var (
	errFallback = errors.New("falling back to generic handler")
	errIgnore   = errors.New("ignoring event")
)

const (
	packetTypeRequest  = 1
	packetTypeResponse = 2

	directionRecv = 0
	directionSend = 1
)

// ReadTCPRequestIntoSpan returns a request.Span from the provided ring buffer record
//
//nolint:cyclop
func ReadTCPRequestIntoSpan(parseCtx *EBPFParseContext, cfg *config.EBPFTracer, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[TCPRequestInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	if !filter.ValidPID(event.Pid.UserPid, event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	// Gate: suppress connections whose parse failure rate is too high.
	// Read-only check: do not mutate the parse window while gating.
	if isConnSuppressed(parseCtx, event.ConnInfo) {
		return request.Span{}, true, nil
	}

	requestBuffer, responseBuffer, payloadTruncated := getBuffers(parseCtx, event)

	if cfg.ProtocolDebug {
		fmt.Printf("[>] %v\n", requestBuffer)
		fmt.Printf("[<] %v\n", responseBuffer)
	}

	span, ignore, parseErr := readTCPRequestIntoSpanInner(parseCtx, cfg, event, requestBuffer, responseBuffer)

	// Map parse result back to outcome for failure rate tracking.
	if parseErr != nil {
		recordParseOutcome(parseCtx, event.ConnInfo, ParseInvalid)
	} else if ignore {
		recordParseOutcome(parseCtx, event.ConnInfo, ParseIgnored)
	} else {
		recordParseOutcome(parseCtx, event.ConnInfo, ParseSuccess)
	}

	if payloadTruncated && !ignore && parseErr == nil {
		request.SetPayloadTruncated(&span)
	}
	return span, ignore, parseErr
}

//nolint:cyclop
func readTCPRequestIntoSpanInner(parseCtx *EBPFParseContext, cfg *config.EBPFTracer, event *TCPRequestInfo, requestBuffer, responseBuffer []byte) (request.Span, bool, error) {
	// We might know already the protocol for this event
	switch event.ProtocolType {
	case ProtocolTypeKafka:
		k, ignore, err := ProcessPossibleKafkaEvent(event, requestBuffer, responseBuffer, parseCtx.kafkaTopicUUIDToName)
		if ignore && err == nil {
			return request.Span{}, true, nil // parsed kafka event, but we don't want to create a span for it
		}
		if err == nil {
			return TCPToKafkaToSpan(event, k), false, nil
		}
		if errors.Is(err, kafkaparser.ErrUnsupportedAPIKey) {
			// Unsupported API key here still means the Kafka frame is valid.
			// Treat it as ignored so it does not raise parse-failure suppression.
			return request.Span{}, true, nil
		}
		return request.Span{}, true, fmt.Errorf("failed to handle Kafka event: %w", err)
	case ProtocolTypeMQTT:
		m, ignore, err := ProcessPossibleMQTTEvent(event, requestBuffer, responseBuffer)
		if ignore && err == nil {
			return request.Span{}, true, nil // parsed MQTT event, but we don't want to create a span for it
		}
		if err == nil {
			return TCPToMQTTToSpan(event, m), false, nil
		}
		return request.Span{}, true, fmt.Errorf("failed to handle MQTT event: %w", err)
	case ProtocolTypeMySQL:
		span, err := handleMySQL(parseCtx, event, requestBuffer, responseBuffer)
		if errors.Is(err, errFallback) {
			slog.Debug("MySQL: falling back to generic handler")
			break
		}
		if errors.Is(err, errIgnore) {
			return request.Span{}, true, nil
		}
		if err != nil {
			return request.Span{}, true, fmt.Errorf("failed to handle MySQL event: %w", err)
		}
		return span, false, nil
	case ProtocolTypePostgres:
		span, err := handlePostgres(parseCtx, event, requestBuffer, responseBuffer)
		if errors.Is(err, errFallback) {
			slog.Debug("Postgres: falling back to generic handler")
			break
		}
		if errors.Is(err, errIgnore) {
			return request.Span{}, true, nil
		}
		if err != nil {
			return request.Span{}, true, fmt.Errorf("failed to handle Postgres event: %w", err)
		}
		return span, false, nil
	case ProtocolTypeMSSQL:
		span, err := handleMSSQL(parseCtx, event, requestBuffer, responseBuffer)
		if errors.Is(err, errFallback) {
			slog.Debug("MSSQL: falling back to generic handler")
			break
		}
		if errors.Is(err, errIgnore) {
			return request.Span{}, true, nil
		}
		if err != nil {
			return request.Span{}, true, fmt.Errorf("failed to handle MSSQL event: %w", err)
		}
		return span, false, nil
	case ProtocolTypeAMQP:
		span, outcome, err := ProcessPossibleAMQPEvent(event, requestBuffer, responseBuffer, parseCtx.amqpLastDestinationCache)
		return protocolOutcomeToSpan(span, outcome, err, "AMQP")
	case ProtocolTypeAMQP1:
		span, outcome, err := ProcessPossibleAMQP10Event(event, requestBuffer, responseBuffer, parseCtx.amqp10LinkAddressCache)
		return protocolOutcomeToSpan(span, outcome, err, "AMQP 1.0")
	case ProtocolTypeOpenWire:
		span, outcome, err := ProcessPossibleOpenWireEvent(event, requestBuffer, responseBuffer, parseCtx.openWireDestinationCache)
		return protocolOutcomeToSpan(span, outcome, err, "OpenWire")
	case ProtocolTypeSTOMP:
		span, outcome, err := ProcessPossibleSTOMPEvent(event, requestBuffer, responseBuffer)
		return protocolOutcomeToSpan(span, outcome, err, "STOMP")
	case ProtocolTypeCQL:
		span, outcome, err := ProcessPossibleCQLEvent(event, requestBuffer, responseBuffer)
		return protocolOutcomeToSpan(span, outcome, err, "CQL")
	case ProtocolTypeNATS:
		span, outcome, err := ProcessPossibleNATSEvent(event, requestBuffer, responseBuffer)
		return protocolOutcomeToSpan(span, outcome, err, "NATS")
	case ProtocolTypeMemcached:
		span, outcome, err := ProcessPossibleMemcachedEvent(event, requestBuffer, responseBuffer)
		return protocolOutcomeToSpan(span, outcome, err, "Memcached")
	case ProtocolTypeClickHouse:
		span, outcome, err := ProcessPossibleClickHouseEvent(event, requestBuffer, responseBuffer)
		return protocolOutcomeToSpan(span, outcome, err, "ClickHouse")
	case ProtocolTypeZooKeeper:
		span, outcome, err := ProcessPossibleZooKeeperEvent(event, requestBuffer, responseBuffer)
		return protocolOutcomeToSpan(span, outcome, err, "ZooKeeper")
	case ProtocolTypeDubbo2:
		span, outcome, err := ProcessPossibleDubbo2Event(event, requestBuffer, responseBuffer)
		return protocolOutcomeToSpan(span, outcome, err, "Dubbo2")
	case ProtocolTypeFDB:
		span, outcome, err := ProcessPossibleFDBEvent(event, requestBuffer, responseBuffer)
		return protocolOutcomeToSpan(span, outcome, err, "FoundationDB")
	case ProtocolTypeSunRPC:
		span, ignore, matched, err := matchSunRPC(parseCtx, event, requestBuffer, responseBuffer)
		if err != nil {
			return request.Span{}, true, fmt.Errorf("failed to handle SunRPC event: %w", err)
		}
		if matched {
			return span, ignore, nil
		}
	case ProtocolTypeUnknown:
	default:
	}

	// Check if we have a SQL statement
	op, table, sql, kind := detectSQLPayload(cfg.HeuristicSQLDetect, requestBuffer)
	if validSQL(op, table, kind) {
		return TCPToSQLToSpan(event, op, table, sql, kind, "", nil), false, nil
	} else {
		op, table, sql, kind = detectSQLPayload(cfg.HeuristicSQLDetect, responseBuffer)
		if validSQL(op, table, kind) {
			reverseTCPEvent(event)
			return TCPToSQLToSpan(event, op, table, sql, kind, "", nil), false, nil
		}
	}

	if maybeFastCGI(requestBuffer) {
		op, uri, status := detectFastCGI(requestBuffer, responseBuffer)
		if status >= 0 {
			return TCPToFastCGIToSpan(event, op, uri, status), false, nil
		}
	}
	mongoInfo := mongoInfoFromEvent(event, requestBuffer, responseBuffer, parseCtx.mongoRequestCache)
	if mongoInfo != nil {
		mongoSpan := TCPToMongoToSpan(event, mongoInfo)
		return mongoSpan, false, nil
	}

	// Check for Couchbase memcached binary protocol
	cbInfo, ignore, err := ProcessPossibleCouchbaseEvent(event, requestBuffer, responseBuffer, parseCtx.couchbaseBucketCache)
	if err == nil {
		if ignore {
			return request.Span{}, true, nil
		}
		if cbInfo != nil {
			return TCPToCouchbaseToSpan(event, cbInfo), false, nil
		}
	}

	// AMQP-family heuristic detection order mirrors the kernel classifier.
	if isAMQP1(requestBuffer) || isAMQP1(responseBuffer) {
		span, outcome, err := ProcessPossibleAMQP10Event(event, requestBuffer, responseBuffer, parseCtx.amqp10LinkAddressCache)
		if result, matched := protocolOutcomeForHeuristic(span, outcome, err, "AMQP 1.0"); matched {
			return result.span, result.ignore, result.err
		}
	}
	if isOpenWire(requestBuffer) || isOpenWire(responseBuffer) {
		span, outcome, err := ProcessPossibleOpenWireEvent(event, requestBuffer, responseBuffer, parseCtx.openWireDestinationCache)
		if result, matched := protocolOutcomeForHeuristic(span, outcome, err, "OpenWire"); matched {
			return result.span, result.ignore, result.err
		}
	}
	if isSTOMP(requestBuffer) || isSTOMP(responseBuffer) {
		span, outcome, err := ProcessPossibleSTOMPEvent(event, requestBuffer, responseBuffer)
		if result, matched := protocolOutcomeForHeuristic(span, outcome, err, "STOMP"); matched {
			return result.span, result.ignore, result.err
		}
	}
	if isAMQP(requestBuffer) || isAMQP(responseBuffer) {
		span, outcome, err := ProcessPossibleAMQPEvent(event, requestBuffer, responseBuffer, parseCtx.amqpLastDestinationCache)
		if result, matched := protocolOutcomeForHeuristic(span, outcome, err, "AMQP"); matched {
			return result.span, result.ignore, result.err
		}
	}

	// CQL heuristic detection
	if isCQL(requestBuffer) || isCQL(responseBuffer) {
		span, outcome, err := ProcessPossibleCQLEvent(event, requestBuffer, responseBuffer)
		if outcome == ParseIgnored && err == nil {
			return request.Span{}, true, nil
		}
		if err == nil {
			return span, false, nil
		}
		slog.Debug("CQL heuristic detection failed, ignoring", "error", err)
	}

	// NATS heuristic detection
	if isNATS(requestBuffer) || isNATS(responseBuffer) {
		span, outcome, err := ProcessPossibleNATSEvent(event, requestBuffer, responseBuffer)
		if outcome == ParseIgnored && err == nil {
			return request.Span{}, true, nil
		}
		if err == nil {
			return span, false, nil
		}
		slog.Debug("NATS heuristic detection failed, ignoring", "error", err)
	}

	// Memcached heuristic detection
	if isMemcached(requestBuffer) || isMemcached(responseBuffer) {
		span, outcome, err := ProcessPossibleMemcachedEvent(event, requestBuffer, responseBuffer)
		if outcome == ParseIgnored && err == nil {
			return request.Span{}, true, nil
		}
		if err == nil {
			return span, false, nil
		}
		slog.Debug("Memcached heuristic detection failed, ignoring", "error", err)
	}

	// ClickHouse heuristic detection
	if isClickHouse(requestBuffer) || isClickHouse(responseBuffer) {
		span, outcome, err := ProcessPossibleClickHouseEvent(event, requestBuffer, responseBuffer)
		if outcome == ParseIgnored && err == nil {
			return request.Span{}, true, nil
		}
		if err == nil {
			return span, false, nil
		}
		slog.Debug("ClickHouse heuristic detection failed, ignoring", "error", err)
	}

	// ZooKeeper heuristic detection
	if isZooKeeper(requestBuffer) || isZooKeeper(responseBuffer) {
		span, outcome, err := ProcessPossibleZooKeeperEvent(event, requestBuffer, responseBuffer)
		if outcome == ParseIgnored && err == nil {
			return request.Span{}, true, nil
		}
		if err == nil {
			return span, false, nil
		}
		slog.Debug("ZooKeeper heuristic detection failed, ignoring", "error", err)
	}

	// Dubbo2 heuristic detection
	if isDubbo2(requestBuffer) || isDubbo2(responseBuffer) {
		span, outcome, err := ProcessPossibleDubbo2Event(event, requestBuffer, responseBuffer)
		if outcome == ParseIgnored && err == nil {
			return request.Span{}, true, nil
		}
		if err == nil {
			return span, false, nil
		}
		slog.Debug("Dubbo2 heuristic detection failed, ignoring", "error", err)
	}

	// FoundationDB heuristic detection
	if isFDB(requestBuffer) || isFDB(responseBuffer) {
		span, outcome, err := ProcessPossibleFDBEvent(event, requestBuffer, responseBuffer)
		if outcome == ParseIgnored && err == nil {
			return request.Span{}, true, nil
		}
		if err == nil {
			return span, false, nil
		}
		slog.Debug("FoundationDB heuristic detection failed, ignoring", "error", err)
	}

	// SunRPC heuristic detection.
	if span, ignore, matched, err := matchSunRPC(parseCtx, event, requestBuffer, responseBuffer); err != nil {
		slog.Debug("SunRPC heuristic detection failed, ignoring", "error", err)
	} else if matched {
		return span, ignore, nil
	}

	switch {
	case isRedis(requestBuffer) && isRedis(responseBuffer):
		op, text, ok := parseRedisRequest(requestBuffer)

		if ok {
			var status int
			var redisErr request.DBError
			if op == "" {
				op, text, ok = parseRedisRequest(responseBuffer)
				if !ok || op == "" {
					return request.Span{}, true, nil // ignore if we couldn't parse it
				}
				// We've caught the event reversed in the middle of communication, let's
				// reverse the event
				reverseTCPEvent(event)
				redisErr, status = redisStatus(requestBuffer)
			} else {
				redisErr, status = redisStatus(responseBuffer)
			}

			db, found := getRedisDB(event.ConnInfo, op, text, parseCtx.redisDBCache)
			if !found {
				db = -1 // if we don't have the db in cache, we assume it's not set
			}
			return TCPToRedisToSpan(event, op, text, status, db, redisErr), false, nil
		}
	case isMQTT(requestBuffer) || isMQTT(responseBuffer):
		m, ignore, err := ProcessPossibleMQTTEvent(event, requestBuffer, responseBuffer)
		if ignore && err == nil {
			return request.Span{}, true, nil // parsed MQTT event, but we don't want to create a span for it
		}
		if err == nil {
			return TCPToMQTTToSpan(event, m), false, nil
		}
		// MQTT heuristic matched but full parsing failed - ignore the packet
		slog.Debug("MQTT heuristic detection failed, ignoring", "error", err)
	default:
		// The kernel may leave a broker connection Unknown (e.g. agent attached mid-connection),
		// so a genuine Kafka frame can reach here and look like HTTP2. Try a strict Kafka parse
		// first: ParseKafkaRequestHeader is strict enough that real HTTP2/gRPC fails it and
		// correctly falls through to the HTTP2 path below.
		if span, ignore, matched := matchKafkaFallback(event, requestBuffer, responseBuffer, parseCtx.kafkaTopicUUIDToName); matched {
			return span, ignore, nil
		}
		// Kafka and gRPC/HTTP2 can look similar; anything that isn't a valid Kafka frame and
		// looks like HTTP2 is handed to the HTTP2 misclassification path.
		if isHTTP2(requestBuffer, int(event.Len)) || isHTTP2(responseBuffer, int(event.RespLen)) {
			evCopy := *event
			MisclassifiedEvents <- MisclassifiedEvent{EventType: EventTypeKHTTP2, TCPInfo: &evCopy}
			return request.Span{}, true, nil // ignore for now, next event will be parsed
		}
	}

	if cfg.ProtocolDebug {
		fmt.Printf("![>] %v\n", requestBuffer)
		fmt.Printf("![<] %v\n", responseBuffer)
	}

	return request.Span{}, true, nil // ignore if we couldn't parse it
}

type protocolHeuristicResult struct {
	span   request.Span
	ignore bool
	err    error
}

func protocolOutcomeToSpan(span request.Span, outcome ParseOutcome, err error, protocolName string) (request.Span, bool, error) {
	switch outcome {
	case ParseSuccess:
		if err != nil {
			return request.Span{}, true, fmt.Errorf("failed to handle %s event: %w", protocolName, err)
		}
		return span, false, nil
	case ParseIgnored, ParseNeedsMore:
		return request.Span{}, true, nil
	case ParseInvalid:
		if err != nil {
			return request.Span{}, true, fmt.Errorf("failed to handle %s event: %w", protocolName, err)
		}
		return request.Span{}, true, fmt.Errorf("failed to handle %s event: invalid frame", protocolName)
	default:
		return request.Span{}, true, nil
	}
}

func protocolOutcomeForHeuristic(
	span request.Span,
	outcome ParseOutcome,
	err error,
	protocolName string,
) (protocolHeuristicResult, bool) {
	switch outcome {
	case ParseSuccess:
		if err != nil {
			slog.Debug(protocolName+" heuristic detection failed, ignoring", "error", err)
			return protocolHeuristicResult{}, false
		}
		return protocolHeuristicResult{span: span, ignore: false, err: nil}, true
	case ParseIgnored, ParseNeedsMore:
		return protocolHeuristicResult{span: request.Span{}, ignore: true, err: nil}, true
	case ParseInvalid:
		if err != nil {
			slog.Debug(protocolName+" heuristic detection failed, ignoring", "error", err)
		}
		return protocolHeuristicResult{}, false
	default:
		return protocolHeuristicResult{}, false
	}
}

func getBuffers(parseCtx *EBPFParseContext, event *TCPRequestInfo) (req []byte, resp []byte, truncated bool) {
	l := int(event.Len)
	if l < 0 || len(event.Buf) < l {
		l = len(event.Buf)
	}
	req = event.Buf[:l]

	l = int(event.RespLen)
	if l < 0 || len(event.Rbuf) < l {
		l = len(event.Rbuf)
	}
	resp = event.Rbuf[:l]

	if event.HasLargeBuffers == 1 {
		if b, payloadTruncated, ok := extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeRequest, directionByPacketType(packetTypeRequest, !event.IsServer), event.ConnInfo); ok {
			req = b
			truncated = truncated || payloadTruncated
		}
		if b, payloadTruncated, ok := extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeResponse, directionByPacketType(packetTypeResponse, !event.IsServer), event.ConnInfo); ok {
			resp = b
			truncated = truncated || payloadTruncated
		}
	}

	return
}

func reverseTCPEvent(trace *TCPRequestInfo) {
	if trace.Direction == 0 {
		trace.Direction = 1
	} else {
		trace.Direction = 0
	}

	port := trace.ConnInfo.S_port
	addr := trace.ConnInfo.S_addr
	trace.ConnInfo.S_addr = trace.ConnInfo.D_addr
	trace.ConnInfo.S_port = trace.ConnInfo.D_port
	trace.ConnInfo.D_addr = addr
	trace.ConnInfo.D_port = port
}
