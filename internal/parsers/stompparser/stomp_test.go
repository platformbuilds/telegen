// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package stompparser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFrameSupportsLFAndCRLFAndHeaderEscapes(t *testing.T) {
	frameLF := []byte("SEND\ndestination:/queue/orders\ncustom:line\\nwith\\ccolon\\\\slash\n\npayload\x00")
	parsed, consumed, err := ParseFrame(frameLF)
	require.NoError(t, err)
	assert.Equal(t, len(frameLF), consumed)
	assert.Equal(t, "SEND", parsed.Command)
	assert.Equal(t, "/queue/orders", parsed.Headers["destination"])
	assert.Equal(t, "line\nwith:colon\\slash", parsed.Headers["custom"])
	assert.Equal(t, "payload", string(parsed.Body))

	frameCRLF := []byte("MESSAGE\r\ndestination:/topic/alerts\r\nsubscription:sub-1\r\n\r\nhello\r\nworld\x00\r\n")
	parsed, consumed, err = ParseFrame(frameCRLF)
	require.NoError(t, err)
	assert.Equal(t, len(frameCRLF), consumed)
	assert.Equal(t, "MESSAGE", parsed.Command)
	assert.Equal(t, "/topic/alerts", parsed.Headers["destination"])
	assert.Equal(t, "sub-1", parsed.Headers["subscription"])
	assert.Equal(t, "hello\r\nworld", string(parsed.Body))
}

func TestParseFrameRejectsNearMissTextBuffer(t *testing.T) {
	nearMiss := []byte("SEN\ndestination:/queue/orders\n\npayload\x00")
	_, _, err := ParseFrame(nearMiss)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown command")
}

func TestIsSTOMP(t *testing.T) {
	assert.True(t, IsSTOMP([]byte("CONNECT\naccept-version:1.2\n\n\x00")))
	assert.False(t, IsSTOMP([]byte("GET / HTTP/1.1\r\nHost:example\r\n\r\n")))
}
