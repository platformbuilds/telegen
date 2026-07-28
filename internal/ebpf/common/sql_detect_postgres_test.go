// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon

import (
	"encoding/binary"
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresMessagesIterator(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    []postgresMessage
		wantErr bool
	}{
		{
			name: "single valid message",
			// Message: type 'Q', length 11, data "SELECT\x00"
			buf: append([]byte{'Q', 0, 0, 0, 11}, append([]byte("SELECT"), 0)...),
			want: []postgresMessage{
				{
					typ:  "QUERY",
					data: append([]byte("SELECT"), 0),
				},
			},
			wantErr: false,
		},
		{
			name: "multiple valid messages",
			buf: func() []byte {
				// First message: type 'Q', length 11, data "SELECT\x00"
				// Second message: type 'Q', length 11, data "COMMIT\x00"
				b := []byte{'Q', 0, 0, 0, 11}
				b = append(b, append([]byte("SELECT"), 0)...)
				b = append(b, 'Q', 0, 0, 0, 11)
				b = append(b, append([]byte("COMMIT"), 0)...)
				return b
			}(),
			want: []postgresMessage{
				{
					typ:  "QUERY",
					data: append([]byte("SELECT"), 0),
				},
				{
					typ:  "QUERY",
					data: append([]byte("COMMIT"), 0),
				},
			},
			wantErr: false,
		},
		{
			name:    "buffer too short for header",
			buf:     []byte{'Q', 0, 0, 0},
			want:    nil,
			wantErr: true,
		},
		{
			name: "buffer too short for message data",
			// Header says length 20, but only 10 bytes in buffer (5 header + 5 data)
			buf:     append([]byte{'Q', 0, 0, 0, 20}, []byte("short")...),
			want:    nil,
			wantErr: true,
		},
		{
			name: "zero length message",
			// Header says length 4 (header only, no data)
			buf: []byte{'Q', 0, 0, 0, 4},
			want: []postgresMessage{
				{
					typ:  "QUERY",
					data: []byte{},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got []postgresMessage
			it := &postgresMessageIterator{buf: tt.buf}
			for {
				msg := it.next()
				if it.isEOF() {
					break
				}
				got = append(got, msg)
			}
			if tt.wantErr {
				assert.Error(t, it.err, "postgresMessageIterator should return an error for test case: %s", tt.name)
				return
			}
			require.NoError(t, it.err, "postgresMessageIterator returned unexpected error for test case: %s", tt.name)
			assert.Len(t, got, len(tt.want), "postgresMessageIterator returned unexpected number of messages for test case: %s", tt.name)
			assert.Equal(t, tt.want, got, "postgresMessageIterator returned unexpected messages for test case: %s", tt.name)
		})
	}
}

func TestPostgresMessagesIteratorNoAllocs(t *testing.T) {
	buf := func() []byte {
		// First message: type 'Q', length 11, data "SELECT\x00"
		// Second message: type 'Q', length 11, data "COMMIT\x00"
		b := []byte{'Q', 0, 0, 0, 11}
		b = append(b, append([]byte("SELECT"), 0)...)
		b = append(b, 'Q', 0, 0, 0, 11)
		b = append(b, append([]byte("COMMIT"), 0)...)
		return b
	}()

	allocs := testing.AllocsPerRun(1000, func() {
		it := &postgresMessageIterator{buf: buf}

		for {
			it.next()
			if it.isEOF() {
				break
			}
		}
	})

	if allocs != 0 {
		t.Errorf("MessageIterator allocated %v allocs per run; want 0", allocs)
	}
}

func buildPostgresFrame(msgType byte, payload []byte) []byte {
	frame := make([]byte, kPgHdrSize+len(payload))
	frame[0] = msgType
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)+4))
	copy(frame[5:], payload)
	return frame
}

func buildMySQLPacket(command byte, payload []byte) []byte {
	packet := make([]byte, 5+len(payload))
	packetLen := len(payload) + 1 // command byte + payload
	packet[0] = byte(packetLen)
	packet[1] = byte(packetLen >> 8)
	packet[2] = byte(packetLen >> 16)
	packet[3] = 0
	packet[4] = command
	copy(packet[5:], payload)
	return packet
}

func TestIsPostgresFrameConsistency(t *testing.T) {
	query := buildPostgresFrame(kPostgresQuery, append([]byte("SELECT 1"), 0))
	require.True(t, isPostgres(query), "single well-formed query frame must be classified as postgres")

	pipelined := append(
		buildPostgresFrame(kPostgresQuery, append([]byte("BEGIN"), 0)),
		buildPostgresFrame(kPostgresBind, []byte{0})...,
	)
	require.True(t, isPostgres(pipelined), "well-formed pipelined Query+Bind frames must be classified as postgres")
}

func TestIsPostgresRejectsMariaDBExecutePacket(t *testing.T) {
	mariaExecute := buildMySQLPacket(kMySQLExecute, []byte{
		0x01, 0x00, 0x00, 0x00, // statement id
		0x00,                   // flags
		0x01, 0x00, 0x00, 0x00, // iteration count
		0x00,       // null-bitmap (1 param)
		0x01,       // new params bound flag
		0x0f, 0x00, // param type: VAR_STRING
		0x03, 'f', 'o', 'o', // value
	})

	require.False(t, isPostgres(mariaExecute), "MariaDB COM_STMT_EXECUTE must not be classified as postgres")
}

func TestDetectSQLPayloadMariaDBPacketsClassifyAsMySQL(t *testing.T) {
	mariaPrepare := buildMySQLPacket(kMySQLPrepare, []byte("SELECT * FROM accounts WHERE id = ?"))
	op, table, sql, kind := detectSQLPayload(true, mariaPrepare)
	require.Equal(t, request.DBMySQL, kind, "COM_STMT_PREPARE must classify as MySQL")
	require.Equal(t, "SELECT", op)
	require.Equal(t, "accounts", table)
	require.Contains(t, sql, "SELECT * FROM accounts")

	mariaExecute := buildMySQLPacket(kMySQLExecute, []byte{
		0x02, 0x00, 0x00, 0x00, // statement id
		0x00,
		0x01, 0x00, 0x00, 0x00,
		0x00,
		0x01,
		0x0f, 0x00,
		0x03, 'b', 'a', 'r',
	})
	op, table, sql, kind = detectSQLPayload(true, mariaExecute)
	require.Equal(t, request.DBMySQL, kind, "COM_STMT_EXECUTE must classify as MySQL even without SQL text")
	require.NotEqual(t, "PREPARED STATEMENT", op, "must never fallback to postgres prepared statement parser")
	require.Equal(t, "", table)
	require.Equal(t, "", sql)
}
