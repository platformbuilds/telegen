// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
)

func TestProcessPossibleSTOMPEventSendFrame(t *testing.T) {
	event := &TCPRequestInfo{ConnInfo: newTestConnInfo(), Direction: directionSend}
	req := []byte("SEND\ndestination:/queue/orders\nreceipt:42\n\nhello\x00")

	span, outcome, err := ProcessPossibleSTOMPEvent(event, req, nil)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)
	assert.Equal(t, request.EventTypeSTOMPClient, span.Type)
	assert.Equal(t, request.MessagingPublish, span.Method)
	assert.Equal(t, "/queue/orders", span.Path)
	require.NotNil(t, span.MessagingInfo)
	assert.Equal(t, "stomp.send", span.MessagingInfo.OperationName)
}

func TestProcessPossibleSTOMPEventMessageResponseIsServerReceive(t *testing.T) {
	event := &TCPRequestInfo{ConnInfo: newTestConnInfo(), Direction: directionSend}
	resp := []byte("MESSAGE\ndestination:/topic/alerts\nsubscription:sub-7\n\npayload\x00")

	span, outcome, err := ProcessPossibleSTOMPEvent(event, nil, resp)
	require.NoError(t, err)
	assert.Equal(t, ParseSuccess, outcome)
	assert.Equal(t, request.EventTypeSTOMPServer, span.Type)
	assert.Equal(t, request.MessagingReceive, span.Method)
	assert.Equal(t, "/topic/alerts", span.Path)
}

func TestProcessPossibleSTOMPEventRejectsNearMiss(t *testing.T) {
	event := &TCPRequestInfo{ConnInfo: newTestConnInfo(), Direction: directionSend}
	nearMiss := []byte("SEN\ndestination:/queue/orders\n\npayload\x00")

	_, outcome, err := ProcessPossibleSTOMPEvent(event, nearMiss, nearMiss)
	require.Error(t, err)
	assert.Equal(t, ParseInvalid, outcome)
}
