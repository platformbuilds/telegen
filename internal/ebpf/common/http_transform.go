// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	ebpfhttp "github.com/mirastacklabs-ai/telegen/internal/ebpf/common/http"
	"github.com/mirastacklabs-ai/telegen/internal/ringbuf"
)

func removeQuery(url string) string {
	idx := strings.IndexByte(url, '?')
	if idx > 0 {
		return url[:idx]
	}
	return url
}

type HTTPInfo struct {
	BPFHTTPInfo
	Method     string
	URL        string
	Host       string
	Peer       string
	HeaderHost string
	Body       string
}

// misses serviceID
func httpInfoToSpanLegacy(info *HTTPInfo) request.Span {
	scheme := "http"
	if info.Ssl == 1 {
		scheme = "https"
	}

	return request.Span{
		Type:           request.EventType(info.Type),
		Method:         info.Method,
		Path:           removeQuery(info.URL),
		Peer:           info.Peer,
		PeerPort:       int(info.ConnInfo.S_port),
		Host:           info.Host,
		HostPort:       int(info.ConnInfo.D_port),
		ContentLength:  int64(info.Len),
		ResponseLength: int64(info.RespLen),
		RequestStart:   int64(info.ReqMonotimeNs),
		Start:          int64(info.StartMonotimeNs),
		End:            int64(info.EndMonotimeNs),
		Status:         int(info.Status),
		TraceID:        info.Tp.TraceId,
		SpanID:         info.Tp.SpanId,
		ParentSpanID:   info.Tp.ParentId,
		TraceFlags:     info.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   info.Pid.HostPid,
			UserPID:   info.Pid.UserPid,
			Namespace: info.Pid.Ns,
		},
		Statement: scheme + request.SchemeHostSeparator + info.HeaderHost,
	}
}

func httpRequestResponseToSpan(parseCtx *EBPFParseContext, event *BPFHTTPInfo, req *http.Request, resp *http.Response) request.Span {
	defer func() { _ = req.Body.Close() }()
	defer func() { _ = resp.Body.Close() }()

	peer, host := (*BPFConnInfo)(&event.ConnInfo).reqHostInfo()

	scheme := req.URL.Scheme
	if scheme == "" {
		if event.Ssl == 1 {
			scheme = "https"
		} else {
			scheme = "http"
		}
	}
	httpSpan := request.Span{
		Type:           request.EventType(event.Type),
		Method:         req.Method,
		Path:           removeQuery(req.URL.String()),
		Peer:           peer,
		PeerPort:       int(event.ConnInfo.S_port),
		Host:           host,
		HostPort:       int(event.ConnInfo.D_port),
		ContentLength:  req.ContentLength,
		ResponseLength: resp.ContentLength,
		RequestStart:   int64(event.ReqMonotimeNs),
		Start:          int64(event.StartMonotimeNs),
		End:            int64(event.EndMonotimeNs),
		Status:         resp.StatusCode,
		TraceID:        event.Tp.TraceId,
		SpanID:         event.Tp.SpanId,
		ParentSpanID:   event.Tp.ParentId,
		TraceFlags:     event.Tp.Flags,
		Pid: request.PidInfo{
			HostPID:   event.Pid.HostPid,
			UserPID:   event.Pid.UserPid,
			Namespace: event.Pid.Ns,
		},
		Statement: scheme + request.SchemeHostSeparator + req.Host,
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.AWS.Enabled {
		span, ok := ebpfhttp.AWSS3Span(&httpSpan, req, resp)
		if ok {
			return span
		}

		span, ok = ebpfhttp.AWSSQSSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if !isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GraphQL.Enabled {
		span, ok := ebpfhttp.GraphQLSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.Elasticsearch.Enabled {
		span, ok := ebpfhttp.ElasticsearchSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	// Host/path anchored detectors first, then header-based provider detectors.
	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Embedding.Enabled {
		span, ok := ebpfhttp.EmbeddingSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Retrieval.Enabled {
		span, ok := ebpfhttp.RetrievalSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.OpenAI.Enabled {
		span, ok := ebpfhttp.OpenAISpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Anthropic.Enabled {
		span, ok := ebpfhttp.AnthropicSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Gemini.Enabled {
		span, ok := ebpfhttp.GeminiSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Rerank.Enabled {
		span, ok := ebpfhttp.RerankSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Qwen.Enabled {
		span, ok := ebpfhttp.QwenSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.Bedrock.Enabled {
		span, ok := ebpfhttp.BedrockSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if isClientEvent(event.Type) && parseCtx != nil && parseCtx.payloadExtraction.HTTP.GenAI.MCP.Enabled {
		span, ok := ebpfhttp.MCPSpan(&httpSpan, req, resp)
		if ok {
			return span
		}
	}

	if parseCtx != nil && parseCtx.httpEnricher != nil {
		parseCtx.httpEnricher.Enrich(&httpSpan, req, resp)
	}

	return httpSpan
}

func ReadHTTPInfoIntoSpan(parseCtx *EBPFParseContext, record *ringbuf.Record, filter ServiceFilter) (request.Span, bool, error) {
	event, err := ReinterpretCast[BPFHTTPInfo](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	// Generated by Go instrumentation
	if !filter.ValidPID(event.Pid.UserPid, event.Pid.Ns, PIDTypeKProbes) {
		return request.Span{}, true, nil
	}

	return HTTPInfoEventToSpan(parseCtx, event)
}

func HTTPInfoEventToSpan(parseCtx *EBPFParseContext, event *BPFHTTPInfo) (request.Span, bool, error) {
	var (
		requestBuffer, responseBuffer []byte
		hasResponse                   bool
		payloadTruncated              bool
		isClient                      = isClientEvent(event.Type)
	)

	if event.HasLargeBuffers == 1 {
		b, requestTruncated, ok := extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeRequest, directionByPacketType(packetTypeRequest, isClient), event.ConnInfo)
		if ok {
			requestBuffer = b
			payloadTruncated = payloadTruncated || requestTruncated
		} else {
			slog.Debug("missing large buffer for HTTP request", "traceID", event.Tp.TraceId, "conn", event.ConnInfo, "packetType", packetTypeRequest)
		}

		b, responseTruncated, ok := extractTCPLargeBuffer(parseCtx, event.Tp.TraceId, packetTypeResponse, directionByPacketType(packetTypeResponse, isClient), event.ConnInfo)
		if ok {
			responseBuffer = b
			hasResponse = true
			payloadTruncated = payloadTruncated || responseTruncated
		} else {
			slog.Debug("missing large buffer for HTTP response", "traceID", event.Tp.TraceId, "conn", event.ConnInfo, "packetType", packetTypeResponse)
		}
	} else {
		requestBuffer = event.Buf[:]
	}

	if parseCtx != nil && !parseCtx.payloadExtraction.Enabled() {
		// There's no need to parse HTTP headers/body,
		// create the span directly.
		span := httpRequestToSpan(event, requestBuffer)
		if payloadTruncated {
			request.SetPayloadTruncated(&span)
		}
		return span, false, nil
	}

	if !hasResponse {
		// Large buffers disabled
		span := httpRequestToSpan(event, requestBuffer)
		if payloadTruncated {
			request.SetPayloadTruncated(&span)
		}
		return span, false, nil
	}

	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(requestBuffer)))
	resp, err2 := httpSafeParseResponse(responseBuffer, req)
	if err != nil || err2 != nil {
		slog.Debug("error while parsing http request or response, falling back to manual HTTP info parsing", "reqErr", err, "respErr", err2)
		span := httpRequestToSpan(event, requestBuffer)
		if payloadTruncated {
			request.SetPayloadTruncated(&span)
		}
		return span, false, nil
	}
	if req != nil && req.Body != nil {
		defer func() { _ = req.Body.Close() }()
	}
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}

	span := httpRequestResponseToSpan(parseCtx, event, req, resp)
	if payloadTruncated {
		request.SetPayloadTruncated(&span)
	}
	return span, false, nil
}

// HTTP response buffers might have been sent incomplete, before the full body.
// Try to parse the original buffer first, if an EOF is encountered, append an empty
// body to the buffer and try again.
func httpSafeParseResponse(responseBuffer []byte, req *http.Request) (*http.Response, error) {
	rd := bufio.NewReader(bytes.NewReader(responseBuffer))
	resp, err := http.ReadResponse(rd, req)
	if err != nil && errors.Is(err, io.ErrUnexpectedEOF) {
		// Append empty body and try again
		responseBuffer := append(responseBuffer, []byte("\r\n\r\n")...)
		rd = bufio.NewReader(bytes.NewReader(responseBuffer))
		return http.ReadResponse(rd, req)
	}
	return resp, nil
}

func httpRequestToSpan(event *BPFHTTPInfo, requestBuffer []byte) request.Span {
	var (
		result     = HTTPInfo{BPFHTTPInfo: *event}
		bufHost    string
		bufPort    int
		parsedHost bool
	)

	// When we can't find the connection info, we signal that through making the
	// source and destination ports equal to max short. E.g. async SSL
	if event.ConnInfo.S_port != 0 || event.ConnInfo.D_port != 0 {
		source, target := (*BPFConnInfo)(&event.ConnInfo).reqHostInfo()
		result.Host = target
		result.Peer = source
	} else {
		bufHost, bufPort = httpHostFromBuf(requestBuffer)
		parsedHost = true

		if bufPort >= 0 && bufPort <= 65535 {
			result.Host = bufHost
			result.ConnInfo.D_port = uint16(bufPort) // Safe: validated above
		}
	}
	result.URL = httpURLFromBuf(requestBuffer)
	result.Method = httpMethodFromBuf(requestBuffer)

	if request.EventType(result.Type) == request.EventTypeHTTPClient && !parsedHost {
		bufHost, _ = httpHostFromBuf(requestBuffer)
	}

	result.HeaderHost = bufHost

	return httpInfoToSpanLegacy(&result)
}

func httpURLFromBuf(req []byte) string {
	bufEnd := requestBufEnd(req)
	if bufEnd == 0 {
		return ""
	}

	space := bytes.IndexByte(req[:bufEnd], ' ')
	if space < 0 {
		return ""
	}
	start := space + 1
	if start >= bufEnd {
		return ""
	}

	end := start
	for end < bufEnd {
		switch req[end] {
		case ' ', '\r', '\n':
			return string(req[start:end])
		}
		end++
	}
	return string(req[start:bufEnd])
}

func httpMethodFromBuf(req []byte) string {
	bufEnd := requestBufEnd(req)
	space := bytes.IndexByte(req[:bufEnd], ' ')
	if space < 0 {
		return ""
	}

	return string(req[:space])
}

func httpHostFromBuf(req []byte) (string, int) {
	bufEnd := requestBufEnd(req)
	if bufEnd == 0 {
		return "", -1
	}

	// Start after the request line.
	lineStart := bytes.IndexByte(req[:bufEnd], '\n')
	if lineStart < 0 {
		return "", -1
	}
	lineStart++

	for lineStart < bufEnd {
		lineEndRel := bytes.IndexByte(req[lineStart:bufEnd], '\n')
		lineEndedByCR := false
		if lineEndRel < 0 {
			lineEndRel = bytes.IndexByte(req[lineStart:bufEnd], '\r')
			if lineEndRel < 0 {
				// only parse full host information, partial may
				// get the wrong name or wrong port
				return "", -1
			}
			lineEndedByCR = true
		}
		lineEnd := lineStart + lineEndRel
		line := req[lineStart:lineEnd]
		if !lineEndedByCR && len(line) > 0 && line[len(line)-1] == '\r' {
			line = line[:len(line)-1]
		}
		if len(line) == 0 {
			break
		}

		if len(line) >= len("Host:") && bytes.Equal(line[:len("Host:")], []byte("Host:")) {
			value := bytes.TrimLeft(line[len("Host:"):], " ")
			if len(value) == 0 {
				return "", -1
			}
			host, port := splitHostPortBytes(value)
			return string(host), port
		}

		lineStart = lineEnd + 1
	}

	return "", -1
}

func requestBufEnd(req []byte) int {
	bufEnd := bytes.IndexByte(req, 0)
	if bufEnd < 0 {
		return len(req)
	}
	return bufEnd
}

func splitHostPortBytes(value []byte) ([]byte, int) {
	if len(value) == 0 {
		return value, -1
	}

	// Bracketed IPv6 host form: [::1]:8080
	if value[0] == '[' {
		closing := bytes.IndexByte(value, ']')
		if closing < 0 {
			return value, -1
		}
		host := value[1:closing]
		if closing+2 > len(value) || value[closing+1] != ':' {
			return host, -1
		}
		if port, ok := parsePositivePort(value[closing+2:]); ok {
			return host, port
		}
		return host, -1
	}

	colon := bytes.LastIndexByte(value, ':')
	if colon <= 0 {
		return value, -1
	}
	// Unbracketed IPv6 should not be interpreted as host:port.
	if bytes.IndexByte(value[:colon], ':') >= 0 {
		return value, -1
	}

	if port, ok := parsePositivePort(value[colon+1:]); ok {
		return value[:colon], port
	}
	return value, -1
}

func parsePositivePort(portBuf []byte) (int, bool) {
	if len(portBuf) == 0 {
		return 0, false
	}
	port := 0
	for _, b := range portBuf {
		if b < '0' || b > '9' {
			return 0, false
		}
		port = port*10 + int(b-'0')
		if port > 65535 {
			return 0, false
		}
	}
	return port, true
}
