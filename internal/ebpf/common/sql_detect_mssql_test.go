package ebpfcommon

import (
	"encoding/binary"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/sqlprune"
)

func TestIsMSSQLAndHandleMSSQLBatch(t *testing.T) {
	payload := ucs2Bytes("SELECT * FROM users")
	req := buildTDSBatchPacket(payload)
	resp := buildTDSResponsePacket(nil)

	require.True(t, isMSSQL(req))
	assert.Equal(t, "SQL_BATCH", sqlprune.SQLParseCommandID(request.DBMSSQL, req))

	event := &TCPRequestInfo{}
	span, err := handleMSSQL(nil, event, req, resp)
	require.NoError(t, err)
	assert.Equal(t, "SELECT", span.Method)
	assert.Equal(t, "users", span.Path)
	assert.Equal(t, int(request.DBMSSQL), span.SubType)
}

func TestMSSQLInvalidPayloadFallsBack(t *testing.T) {
	event := &TCPRequestInfo{}
	_, err := handleMSSQL(nil, event, []byte("bad"), []byte{})
	require.ErrorIs(t, err, errFallback)
}

func buildTDSBatchPacket(payload []byte) []byte {
	total := kMSSQLHeaderLen + len(payload)
	b := make([]byte, total)
	b[0] = kMSSQLBatch
	b[1] = 0x01
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	// SPID + packet id left as zero.
	b[7] = 0x00
	copy(b[kMSSQLHeaderLen:], payload)
	return b
}

func buildTDSResponsePacket(payload []byte) []byte {
	total := kMSSQLHeaderLen + len(payload)
	b := make([]byte, total)
	b[0] = kMSSQLResponse
	b[1] = 0x01
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[7] = 0x00
	copy(b[kMSSQLHeaderLen:], payload)
	return b
}

func ucs2Bytes(s string) []byte {
	runes := []rune(s)
	u16 := utf16.Encode(runes)
	out := make([]byte, 0, len(u16)*2)
	for _, v := range u16 {
		var tmp [2]byte
		binary.LittleEndian.PutUint16(tmp[:], v)
		out = append(out, tmp[:]...)
	}
	return out
}
