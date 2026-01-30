// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package semconv

import (
	"go.opentelemetry.io/otel/attribute"
)

// HTTP attribute keys following OTel semantic conventions v1.27.0
// These follow the new stable HTTP semantic conventions.
const (
	// HTTP request attributes (stable)
	HTTPRequestMethodKey         = "http.request.method"
	HTTPRequestMethodOriginalKey = "http.request.method_original"
	HTTPRequestBodySizeKey       = "http.request.body.size"
	HTTPRequestHeaderKey         = "http.request.header"
	HTTPRequestResendCountKey    = "http.request.resend_count"

	// HTTP response attributes (stable)
	HTTPResponseStatusCodeKey = "http.response.status_code"
	HTTPResponseBodySizeKey   = "http.response.body.size"
	HTTPResponseHeaderKey     = "http.response.header"

	// URL attributes (stable)
	URLSchemeKey   = "url.scheme"
	URLFullKey     = "url.full"
	URLPathKey     = "url.path"
	URLQueryKey    = "url.query"
	URLFragmentKey = "url.fragment"

	// HTTP route (stable)
	HTTPRouteKey = "http.route"

	// Network attributes for HTTP
	NetworkProtocolNameKey    = "network.protocol.name"
	NetworkProtocolVersionKey = "network.protocol.version"

	// Server attributes
	ServerAddressKey = "server.address"
	ServerPortKey    = "server.port"

	// Client attributes
	ClientAddressKey = "client.address"
	ClientPortKey    = "client.port"

	// User agent
	UserAgentOriginalKey = "user_agent.original"

	// Error type
	ErrorTypeKey = "error.type"

	// Legacy HTTP attributes (deprecated but still in use)
	HTTPMethodKey                = "http.method"
	HTTPStatusCodeKey            = "http.status_code"
	HTTPTargetKey                = "http.target"
	HTTPURLKey                   = "http.url"
	HTTPSchemeKey                = "http.scheme"
	HTTPFlavorKey                = "http.flavor"
	HTTPRequestContentLengthKey  = "http.request_content_length"
	HTTPResponseContentLengthKey = "http.response_content_length"
)

// HTTP request method values
const (
	HTTPMethodConnect = "CONNECT"
	HTTPMethodDelete  = "DELETE"
	HTTPMethodGet     = "GET"
	HTTPMethodHead    = "HEAD"
	HTTPMethodOptions = "OPTIONS"
	HTTPMethodPatch   = "PATCH"
	HTTPMethodPost    = "POST"
	HTTPMethodPut     = "PUT"
	HTTPMethodTrace   = "TRACE"
	HTTPMethodOther   = "_OTHER"
)

// registerHTTPAttributes registers all HTTP semantic conventions.
func registerHTTPAttributes(r *Registry) {
	// Stable HTTP request attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         HTTPRequestMethodKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "HTTP request method",
		Examples:    []string{"GET", "POST", "PUT", "DELETE"},
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         HTTPRequestMethodOriginalKey,
		Type:        AttributeTypeString,
		Requirement: RequirementConditionallyRequired,
		Brief:       "Original HTTP method if not standard",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         HTTPRequestBodySizeKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementOptIn,
		Brief:       "Size of the request body in bytes",
		Stability:   StabilityStable,
	})

	// Stable HTTP response attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         HTTPResponseStatusCodeKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementConditionallyRequired,
		Brief:       "HTTP response status code",
		Examples:    []string{"200", "404", "500"},
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         HTTPResponseBodySizeKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementOptIn,
		Brief:       "Size of the response body in bytes",
		Stability:   StabilityStable,
	})

	// URL attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         URLSchemeKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "URL scheme (http, https)",
		Examples:    []string{"http", "https"},
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         URLFullKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Full URL",
		Stability:   StabilityStable,
		Note:        "Should be sanitized to remove credentials",
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         URLPathKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "URL path",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         URLQueryKey,
		Type:        AttributeTypeString,
		Requirement: RequirementConditionallyRequired,
		Brief:       "URL query string",
		Stability:   StabilityStable,
	})

	// HTTP route
	r.RegisterAttribute(&AttributeDefinition{
		Key:         HTTPRouteKey,
		Type:        AttributeTypeString,
		Requirement: RequirementConditionallyRequired,
		Brief:       "Matched route template",
		Examples:    []string{"/users/:id", "/api/v1/orders"},
		Stability:   StabilityStable,
	})

	// Server/client attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ServerAddressKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "Server address (hostname or IP)",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ServerPortKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementConditionallyRequired,
		Brief:       "Server port number",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ClientAddressKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Client address (IP)",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ClientPortKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementOptIn,
		Brief:       "Client port number",
		Stability:   StabilityStable,
	})

	// User agent
	r.RegisterAttribute(&AttributeDefinition{
		Key:         UserAgentOriginalKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Original user agent string",
		Stability:   StabilityStable,
	})

	// Error type
	r.RegisterAttribute(&AttributeDefinition{
		Key:         ErrorTypeKey,
		Type:        AttributeTypeString,
		Requirement: RequirementConditionallyRequired,
		Brief:       "Error type for failed requests",
		Stability:   StabilityStable,
	})

	// Register HTTP metrics
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricHTTPServerRequestDuration,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Duration of HTTP server requests",
		Stability: StabilityStable,
		Attributes: []string{
			HTTPRequestMethodKey,
			HTTPResponseStatusCodeKey,
			HTTPRouteKey,
			URLSchemeKey,
			ServerAddressKey,
			ServerPortKey,
			NetworkProtocolVersionKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricHTTPServerActiveRequests,
		Type:      MetricTypeUpDownCounter,
		Unit:      "{request}",
		Brief:     "Number of active HTTP server requests",
		Stability: StabilityStable,
		Attributes: []string{
			HTTPRequestMethodKey,
			URLSchemeKey,
			ServerAddressKey,
			ServerPortKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricHTTPServerRequestSize,
		Type:      MetricTypeHistogram,
		Unit:      "By",
		Brief:     "Size of HTTP server request bodies",
		Stability: StabilityStable,
		Attributes: []string{
			HTTPRequestMethodKey,
			HTTPResponseStatusCodeKey,
			HTTPRouteKey,
			URLSchemeKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricHTTPServerResponseSize,
		Type:      MetricTypeHistogram,
		Unit:      "By",
		Brief:     "Size of HTTP server response bodies",
		Stability: StabilityStable,
		Attributes: []string{
			HTTPRequestMethodKey,
			HTTPResponseStatusCodeKey,
			HTTPRouteKey,
			URLSchemeKey,
		},
	})

	// HTTP client metrics
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricHTTPClientRequestDuration,
		Type:      MetricTypeHistogram,
		Unit:      "s",
		Brief:     "Duration of HTTP client requests",
		Stability: StabilityStable,
		Attributes: []string{
			HTTPRequestMethodKey,
			HTTPResponseStatusCodeKey,
			ServerAddressKey,
			ServerPortKey,
		},
	})
}

// HTTPServerAttributes provides a builder for HTTP server span attributes.
type HTTPServerAttributes struct {
	attrs []attribute.KeyValue
}

// NewHTTPServerAttributes creates a new HTTP server attributes builder.
func NewHTTPServerAttributes() *HTTPServerAttributes {
	return &HTTPServerAttributes{attrs: make([]attribute.KeyValue, 0, 16)}
}

// Method sets the HTTP request method.
func (h *HTTPServerAttributes) Method(method string) *HTTPServerAttributes {
	if method != "" {
		h.attrs = append(h.attrs, attribute.String(HTTPRequestMethodKey, method))
	}
	return h
}

// StatusCode sets the HTTP response status code.
func (h *HTTPServerAttributes) StatusCode(code int) *HTTPServerAttributes {
	h.attrs = append(h.attrs, attribute.Int(HTTPResponseStatusCodeKey, code))
	return h
}

// Route sets the HTTP route.
func (h *HTTPServerAttributes) Route(route string) *HTTPServerAttributes {
	if route != "" {
		h.attrs = append(h.attrs, attribute.String(HTTPRouteKey, route))
	}
	return h
}

// URLScheme sets the URL scheme.
func (h *HTTPServerAttributes) URLScheme(scheme string) *HTTPServerAttributes {
	if scheme != "" {
		h.attrs = append(h.attrs, attribute.String(URLSchemeKey, scheme))
	}
	return h
}

// URLPath sets the URL path.
func (h *HTTPServerAttributes) URLPath(path string) *HTTPServerAttributes {
	if path != "" {
		h.attrs = append(h.attrs, attribute.String(URLPathKey, path))
	}
	return h
}

// URLQuery sets the URL query string.
func (h *HTTPServerAttributes) URLQuery(query string) *HTTPServerAttributes {
	if query != "" {
		h.attrs = append(h.attrs, attribute.String(URLQueryKey, query))
	}
	return h
}

// ServerAddress sets the server address.
func (h *HTTPServerAttributes) ServerAddress(addr string) *HTTPServerAttributes {
	if addr != "" {
		h.attrs = append(h.attrs, attribute.String(ServerAddressKey, addr))
	}
	return h
}

// ServerPort sets the server port.
func (h *HTTPServerAttributes) ServerPort(port int) *HTTPServerAttributes {
	h.attrs = append(h.attrs, attribute.Int(ServerPortKey, port))
	return h
}

// ClientAddress sets the client address.
func (h *HTTPServerAttributes) ClientAddress(addr string) *HTTPServerAttributes {
	if addr != "" {
		h.attrs = append(h.attrs, attribute.String(ClientAddressKey, addr))
	}
	return h
}

// ClientPort sets the client port.
func (h *HTTPServerAttributes) ClientPort(port int) *HTTPServerAttributes {
	h.attrs = append(h.attrs, attribute.Int(ClientPortKey, port))
	return h
}

// UserAgent sets the user agent string.
func (h *HTTPServerAttributes) UserAgent(ua string) *HTTPServerAttributes {
	if ua != "" {
		h.attrs = append(h.attrs, attribute.String(UserAgentOriginalKey, ua))
	}
	return h
}

// RequestBodySize sets the request body size.
func (h *HTTPServerAttributes) RequestBodySize(size int64) *HTTPServerAttributes {
	h.attrs = append(h.attrs, attribute.Int64(HTTPRequestBodySizeKey, size))
	return h
}

// ResponseBodySize sets the response body size.
func (h *HTTPServerAttributes) ResponseBodySize(size int64) *HTTPServerAttributes {
	h.attrs = append(h.attrs, attribute.Int64(HTTPResponseBodySizeKey, size))
	return h
}

// NetworkProtocolName sets the network protocol name.
func (h *HTTPServerAttributes) NetworkProtocolName(name string) *HTTPServerAttributes {
	if name != "" {
		h.attrs = append(h.attrs, attribute.String(NetworkProtocolNameKey, name))
	}
	return h
}

// NetworkProtocolVersion sets the network protocol version.
func (h *HTTPServerAttributes) NetworkProtocolVersion(version string) *HTTPServerAttributes {
	if version != "" {
		h.attrs = append(h.attrs, attribute.String(NetworkProtocolVersionKey, version))
	}
	return h
}

// ErrorType sets the error type.
func (h *HTTPServerAttributes) ErrorType(errType string) *HTTPServerAttributes {
	if errType != "" {
		h.attrs = append(h.attrs, attribute.String(ErrorTypeKey, errType))
	}
	return h
}

// Build returns the accumulated attributes.
func (h *HTTPServerAttributes) Build() []attribute.KeyValue {
	return h.attrs
}

// HTTPClientAttributes provides a builder for HTTP client span attributes.
type HTTPClientAttributes struct {
	attrs []attribute.KeyValue
}

// NewHTTPClientAttributes creates a new HTTP client attributes builder.
func NewHTTPClientAttributes() *HTTPClientAttributes {
	return &HTTPClientAttributes{attrs: make([]attribute.KeyValue, 0, 16)}
}

// Method sets the HTTP request method.
func (h *HTTPClientAttributes) Method(method string) *HTTPClientAttributes {
	if method != "" {
		h.attrs = append(h.attrs, attribute.String(HTTPRequestMethodKey, method))
	}
	return h
}

// StatusCode sets the HTTP response status code.
func (h *HTTPClientAttributes) StatusCode(code int) *HTTPClientAttributes {
	h.attrs = append(h.attrs, attribute.Int(HTTPResponseStatusCodeKey, code))
	return h
}

// URLFull sets the full URL.
func (h *HTTPClientAttributes) URLFull(url string) *HTTPClientAttributes {
	if url != "" {
		h.attrs = append(h.attrs, attribute.String(URLFullKey, url))
	}
	return h
}

// ServerAddress sets the server address.
func (h *HTTPClientAttributes) ServerAddress(addr string) *HTTPClientAttributes {
	if addr != "" {
		h.attrs = append(h.attrs, attribute.String(ServerAddressKey, addr))
	}
	return h
}

// ServerPort sets the server port.
func (h *HTTPClientAttributes) ServerPort(port int) *HTTPClientAttributes {
	h.attrs = append(h.attrs, attribute.Int(ServerPortKey, port))
	return h
}

// ResendCount sets the request resend count.
func (h *HTTPClientAttributes) ResendCount(count int) *HTTPClientAttributes {
	if count > 0 {
		h.attrs = append(h.attrs, attribute.Int(HTTPRequestResendCountKey, count))
	}
	return h
}

// ErrorType sets the error type.
func (h *HTTPClientAttributes) ErrorType(errType string) *HTTPClientAttributes {
	if errType != "" {
		h.attrs = append(h.attrs, attribute.String(ErrorTypeKey, errType))
	}
	return h
}

// Build returns the accumulated attributes.
func (h *HTTPClientAttributes) Build() []attribute.KeyValue {
	return h.attrs
}

// Metric name constants for HTTP
const (
	MetricHTTPServerRequestDuration = "http.server.request.duration"
	MetricHTTPServerActiveRequests  = "http.server.active_requests"
	MetricHTTPServerRequestSize     = "http.server.request.body.size"
	MetricHTTPServerResponseSize    = "http.server.response.body.size"
	MetricHTTPClientRequestDuration = "http.client.request.duration"
	MetricHTTPClientRequestSize     = "http.client.request.body.size"
	MetricHTTPClientResponseSize    = "http.client.response.body.size"
)
