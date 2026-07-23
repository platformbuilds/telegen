package sunrpcparser

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mirastacklabs-ai/telegen/internal/largebuf"
)

func TestParse_CALL_AUTH_NULL(t *testing.T) {
	const xid = uint32(0x01020304)
	record := buildCallRecord(t, callParams{
		xid:        xid,
		prog:       ProgramNFS,
		vers:       3,
		proc:       3,
		authFlavor: authNull,
	})

	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	res, err := Parse(&reader)
	require.NoError(t, err)
	require.True(t, res.LooksLikeSunRPC)
	require.NotNil(t, res.Call)
	assert.Equal(t, xid, res.Call.Xid)
	assert.Equal(t, uint32(ProgramNFS), res.Call.Program)
	assert.Equal(t, uint32(3), res.Call.Version)
	assert.Equal(t, uint32(3), res.Call.Procedure)
	assert.Equal(t, uint32(authNull), res.Call.AuthFlavor)
}

func TestParse_CALL_and_REPLY(t *testing.T) {
	const xid = uint32(99)
	call := buildCallRecord(t, callParams{
		xid:        xid,
		prog:       ProgramMount,
		vers:       3,
		proc:       1,
		authFlavor: authUnix,
		authBody:   make([]byte, 32),
	})
	reply := buildAcceptedReplyRecord(t, xid, acceptSuccess)

	payload := append(wrapTCPRecord(call), wrapTCPRecord(reply)...)
	buf := largebuf.NewLargeBufferFrom(payload)
	reader := buf.NewReader()

	res, err := Parse(&reader)
	require.NoError(t, err)
	require.NotNil(t, res.Call)
	require.NotNil(t, res.Reply)
	assert.True(t, res.Reply.MatchCallXid)
	assert.Equal(t, uint32(acceptSuccess), res.Reply.AcceptStat)
}

func TestParse_fragmentedCALL(t *testing.T) {
	record := buildCallRecord(t, callParams{
		xid:        1,
		prog:       ProgramPortmapper,
		vers:       2,
		proc:       0,
		authFlavor: authNull,
	})
	payload := wrapTCPRecordFragments(record[:8], record[8:])
	buf := largebuf.NewLargeBufferFrom(payload)
	reader := buf.NewReader()

	res, err := Parse(&reader)
	require.NoError(t, err)
	require.NotNil(t, res.Call)
	assert.Equal(t, uint32(ProgramPortmapper), res.Call.Program)
}

func TestParse_rejectsTooManyRecordFragments(t *testing.T) {
	record := buildCallRecord(t, callParams{
		xid:        1,
		prog:       ProgramPortmapper,
		vers:       2,
		proc:       0,
		authFlavor: authNull,
	})
	fragments := make([][]byte, 0, maxRecordFragments+1)
	for range maxRecordFragments {
		fragments = append(fragments, nil)
	}
	fragments = append(fragments, record)

	buf := largebuf.NewLargeBufferFrom(wrapTCPRecordFragments(fragments...))
	reader := buf.NewReader()

	_, err := Parse(&reader)
	assert.ErrorIs(t, err, ErrNotSunRPC)
}

func TestIsLikelySunRPC_acceptsValidCall(t *testing.T) {
	record := buildCallRecord(t, callParams{
		xid:        1,
		prog:       ProgramPortmapper,
		vers:       2,
		proc:       0,
		authFlavor: authNull,
	})
	buf := largebuf.NewLargeBufferFrom(wrapTCPRecord(record))
	reader := buf.NewReader()

	assert.True(t, IsLikelySunRPC(&reader))
}

func TestParse_notSunRPC(t *testing.T) {
	buf := largebuf.NewLargeBufferFrom([]byte("GET / HTTP/1.1\r\n"))
	reader := buf.NewReader()

	_, err := Parse(&reader)
	assert.ErrorIs(t, err, ErrNotSunRPC)
}

type callParams struct {
	xid        uint32
	prog       uint32
	vers       uint32
	proc       uint32
	authFlavor uint32
	authBody   []byte
	verfFlavor uint32
}

func buildCallRecord(t *testing.T, p callParams) []byte {
	t.Helper()

	body := make([]byte, 0, 64)
	body = appendU32(body, rpcVersion)
	body = appendU32(body, p.prog)
	body = appendU32(body, p.vers)
	body = appendU32(body, p.proc)
	body = appendOpaqueAuth(body, p.authFlavor, p.authBody)
	verfFlavor := uint32(authNull)
	if p.verfFlavor != 0 {
		verfFlavor = p.verfFlavor
	}
	body = appendOpaqueAuth(body, verfFlavor, nil)

	msg := make([]byte, 0, 8+len(body))
	msg = appendU32(msg, p.xid)
	msg = appendU32(msg, msgCall)
	msg = append(msg, body...)
	return msg
}

func buildAcceptedReplyRecord(t *testing.T, xid uint32, acceptStat uint32) []byte {
	t.Helper()

	body := make([]byte, 0, 32)
	body = appendU32(body, replyAccepted)
	body = appendOpaqueAuth(body, authNull, nil)
	body = appendU32(body, acceptStat)

	msg := make([]byte, 0, 8+len(body))
	msg = appendU32(msg, xid)
	msg = appendU32(msg, msgReply)
	msg = append(msg, body...)
	return msg
}

func wrapTCPRecord(record []byte) []byte {
	return wrapTCPRecordFragments(record)
}

// wrapTCPRecordFragments encodes one RPC-over-TCP record using RFC 5531
// record marking.
func wrapTCPRecordFragments(fragments ...[]byte) []byte {
	var out []byte
	for i, fragment := range fragments {
		if len(fragment) > rmFragLen {
			panic("SunRPC test fragment exceeds record-marking length")
		}
		hdr := uint32(len(fragment))
		if i == len(fragments)-1 {
			hdr |= rmLastFrag
		}
		out = appendU32(out, hdr)
		out = append(out, fragment...)
	}
	return out
}

func appendU32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func appendOpaqueAuth(b []byte, flavor uint32, data []byte) []byte {
	b = appendU32(b, flavor)
	b = appendU32(b, uint32(len(data)))
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}
