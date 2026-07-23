package ebpfcommon

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/parsers/sunrpcparser"
)

func TestMatchSunRPC_NFSCallClientSpan(t *testing.T) {
	call := buildSunRPCCallRecord(7, sunrpcparser.ProgramNFS, 3, 6, sunrpcparser.AuthFlavorName(6))
	reply := buildSunRPCAcceptedReply(7)

	event := &TCPRequestInfo{Direction: directionSend}
	req := append(wrapSunRPCTCPRecord(call), wrapSunRPCTCPRecord(reply)...)
	resp := []byte{}

	span, ignore, matched, err := matchSunRPC(NewEBPFParseContext(nil, nil, nil), event, req, resp)
	require.NoError(t, err)
	require.True(t, matched)
	assert.False(t, ignore)
	assert.Equal(t, request.EventTypeSunRPCClient, span.Type)
	assert.Equal(t, "nfs", span.Path)
	assert.Equal(t, "6", span.Method)
	assert.Contains(t, span.Statement, "rpcsec_gss")
}

func TestMatchSunRPC_ServerSpan(t *testing.T) {
	call := buildSunRPCCallRecord(9, sunrpcparser.ProgramMount, 3, 1, "auth_null")
	event := &TCPRequestInfo{Direction: directionRecv}

	span, ignore, matched, err := matchSunRPC(NewEBPFParseContext(nil, nil, nil), event, wrapSunRPCTCPRecord(call), nil)
	require.NoError(t, err)
	require.True(t, matched)
	assert.False(t, ignore)
	assert.Equal(t, request.EventTypeSunRPCServer, span.Type)
	assert.Equal(t, "mount", span.Path)
}

func TestMatchSunRPC_ReplyOnlyClientSpan(t *testing.T) {
	reply := buildSunRPCAcceptedReply(9)
	event := &TCPRequestInfo{Direction: directionRecv}

	span, ignore, matched, err := matchSunRPC(NewEBPFParseContext(nil, nil, nil), event, wrapSunRPCTCPRecord(reply), nil)
	require.NoError(t, err)
	require.True(t, matched)
	assert.False(t, ignore)
	assert.Equal(t, request.EventTypeSunRPCClient, span.Type)
	assert.Equal(t, request.SunRPCSyntheticReplyMethod, span.Method)
}

func TestMatchSunRPC_NotSunRPC(t *testing.T) {
	event := &TCPRequestInfo{}

	_, _, matched, err := matchSunRPC(NewEBPFParseContext(nil, nil, nil), event, []byte("NOT RPC"), nil)
	require.NoError(t, err)
	assert.False(t, matched)
}

func buildSunRPCCallRecord(xid, prog, vers, proc uint32, authFlavor string) []byte {
	var flavor uint32
	switch authFlavor {
	case "rpcsec_gss":
		flavor = 6
	default:
		flavor = 0
	}

	body := appendU32BE(nil, 2)
	body = appendU32BE(body, prog)
	body = appendU32BE(body, vers)
	body = appendU32BE(body, proc)
	body = appendOpaque(body, flavor, nil)
	body = appendOpaque(body, 0, nil)

	msg := appendU32BE(nil, xid)
	msg = appendU32BE(msg, 0)
	msg = append(msg, body...)
	return msg
}

func buildSunRPCAcceptedReply(xid uint32) []byte {
	body := appendU32BE(nil, 0)
	body = appendOpaque(body, 0, nil)
	body = appendU32BE(body, 0)

	msg := appendU32BE(nil, xid)
	msg = appendU32BE(msg, 1)
	msg = append(msg, body...)
	return msg
}

func wrapSunRPCTCPRecord(record []byte) []byte {
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, 0x80000000|uint32(len(record)))
	return append(hdr, record...)
}

func appendU32BE(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func appendOpaque(b []byte, flavor uint32, data []byte) []byte {
	b = appendU32BE(b, flavor)
	b = appendU32BE(b, uint32(len(data)))
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}
