// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package kafkaparser // import "github.com/mirastacklabs-ai/telegen/internal/parsers/kafkaparser"

import "errors"

// JoinGroupRequest contains the fields extracted from a Kafka JoinGroup request.
// JoinGroup (API key 11) is sent by consumers when joining or rejoining a consumer group.
type JoinGroupRequest struct {
	GroupID string
	MemberID string
}

// ParseJoinGroupRequest parses the JoinGroup request to extract the consumer group ID.
// JoinGroup Request (Version: 0+) => group_id session_timeout_ms rebalance_timeout_ms member_id ...
//
//	group_id          => STRING
//	session_timeout_ms => INT32
//	rebalance_timeout_ms => INT32 (version >= 1)
//	member_id         => STRING
func ParseJoinGroupRequest(pkt []byte, header *KafkaRequestHeader, offset Offset) (*JoinGroupRequest, error) {
	if len(pkt) <= offset {
		return nil, errors.New("packet too short for JoinGroup request")
	}

	// group_id: STRING
	groupID, newOffset, err := readString(pkt, header, offset, false)
	if err != nil {
		return nil, err
	}
	offset = newOffset

	// session_timeout_ms: INT32
	_, offset, err = readInt32(pkt, offset)
	if err != nil {
		return nil, err
	}

	// rebalance_timeout_ms: INT32 (version >= 1)
	if header.APIVersion >= 1 {
		_, offset, err = readInt32(pkt, offset)
		if err != nil {
			return nil, err
		}
	}

	// member_id: STRING
	memberID, _, err := readString(pkt, header, offset, false)
	if err != nil {
		// member_id is optional for new members — treat failure as empty
		memberID = ""
	}

	return &JoinGroupRequest{
		GroupID:  groupID,
		MemberID: memberID,
	}, nil
}
