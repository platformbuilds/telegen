// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package semconv

import (
	"go.opentelemetry.io/otel/attribute"
)

// Network attribute keys following OTel semantic conventions v1.27.0
const (
	// Network transport attributes (stable)
	NetworkTransportKey   = "network.transport"
	NetworkTypeKey        = "network.type"
	NetworkIoDirectionKey = "network.io.direction"

	// Network peer attributes
	NetworkPeerAddressKey = "network.peer.address"
	NetworkPeerPortKey    = "network.peer.port"

	// Network local attributes
	NetworkLocalAddressKey = "network.local.address"
	NetworkLocalPortKey    = "network.local.port"

	// Network connection attributes
	NetworkConnectionTypeKey    = "network.connection.type"
	NetworkConnectionSubtypeKey = "network.connection.subtype"
	NetworkCarrierNameKey       = "network.carrier.name"
	NetworkCarrierMccKey        = "network.carrier.mcc"
	NetworkCarrierMncKey        = "network.carrier.mnc"
	NetworkCarrierIccKey        = "network.carrier.icc"

	// DNS attributes
	DNSQuestionNameKey = "dns.question.name"
	DNSQuestionTypeKey = "dns.question.type"
	DNSAnswerClassKey  = "dns.answer.class"
	DNSAnswerNameKey   = "dns.answer.name"
	DNSAnswerTypeKey   = "dns.answer.type"
	DNSAnswerRdataKey  = "dns.answer.rdata"

	// TLS attributes
	TLSCipherKey            = "tls.cipher"
	TLSClientCertificateKey = "tls.client.certificate"
	TLSClientHashSha256Key  = "tls.client.hash.sha256"
	TLSClientIssuerKey      = "tls.client.issuer"
	TLSClientServerNameKey  = "tls.client.server_name"
	TLSClientSubjectKey     = "tls.client.subject"
	TLSProtocolNameKey      = "tls.protocol.name"
	TLSProtocolVersionKey   = "tls.protocol.version"
	TLSServerCertificateKey = "tls.server.certificate"
	TLSServerHashSha256Key  = "tls.server.hash.sha256"
	TLSServerIssuerKey      = "tls.server.issuer"
	TLSServerSubjectKey     = "tls.server.subject"
	TLSResumedKey           = "tls.resumed"
	TLSNextProtocolKey      = "tls.next_protocol"

	// Legacy net.* attributes (deprecated)
	NetHostNameKey     = "net.host.name"
	NetHostPortKey     = "net.host.port"
	NetPeerNameKey     = "net.peer.name"
	NetPeerPortKey     = "net.peer.port"
	NetTransportKey    = "net.transport"
	NetSockPeerAddrKey = "net.sock.peer.addr"
	NetSockPeerPortKey = "net.sock.peer.port"
	NetSockHostAddrKey = "net.sock.host.addr"
	NetSockHostPortKey = "net.sock.host.port"
	NetSockFamilyKey   = "net.sock.family"
)

// Network transport values
const (
	NetworkTransportTCP  = "tcp"
	NetworkTransportUDP  = "udp"
	NetworkTransportPipe = "pipe"
	NetworkTransportUnix = "unix"
	NetworkTransportQUIC = "quic"
)

// Network type values
const (
	NetworkTypeIPv4 = "ipv4"
	NetworkTypeIPv6 = "ipv6"
)

// Network IO direction values
const (
	NetworkIODirectionTransmit = "transmit"
	NetworkIODirectionReceive  = "receive"
)

// Network connection type values
const (
	NetworkConnectionTypeWifi        = "wifi"
	NetworkConnectionTypeWired       = "wired"
	NetworkConnectionTypeCell        = "cell"
	NetworkConnectionTypeUnavailable = "unavailable"
	NetworkConnectionTypeUnknown     = "unknown"
)

// TLS protocol name values
const (
	TLSProtocolTLS  = "tls"
	TLSProtocolSSL  = "ssl"
	TLSProtocolDTLS = "dtls"
)

// registerNetworkAttributes registers all network semantic conventions.
func registerNetworkAttributes(r *Registry) {
	// Network transport attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         NetworkTransportKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Transport protocol",
		Examples:    []string{"tcp", "udp", "quic"},
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         NetworkTypeKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Network layer protocol type",
		Examples:    []string{"ipv4", "ipv6"},
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         NetworkProtocolNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Application layer protocol",
		Examples:    []string{"http", "https", "grpc"},
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         NetworkProtocolVersionKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Application layer protocol version",
		Examples:    []string{"1.0", "1.1", "2", "3"},
		Stability:   StabilityStable,
	})

	// Network peer attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         NetworkPeerAddressKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "Peer address (IP or hostname)",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         NetworkPeerPortKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementRecommended,
		Brief:       "Peer port number",
		Stability:   StabilityStable,
	})

	// Network local attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         NetworkLocalAddressKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "Local address",
		Stability:   StabilityStable,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         NetworkLocalPortKey,
		Type:        AttributeTypeInt,
		Requirement: RequirementOptIn,
		Brief:       "Local port number",
		Stability:   StabilityStable,
	})

	// IO direction
	r.RegisterAttribute(&AttributeDefinition{
		Key:         NetworkIoDirectionKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "Direction of network IO",
		Examples:    []string{"transmit", "receive"},
		Stability:   StabilityStable,
	})

	// TLS attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         TLSProtocolNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "TLS protocol name",
		Examples:    []string{"tls", "ssl"},
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         TLSProtocolVersionKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "TLS protocol version",
		Examples:    []string{"1.2", "1.3"},
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         TLSCipherKey,
		Type:        AttributeTypeString,
		Requirement: RequirementOptIn,
		Brief:       "TLS cipher suite",
		Stability:   StabilityExperimental,
	})

	// DNS attributes
	r.RegisterAttribute(&AttributeDefinition{
		Key:         DNSQuestionNameKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRequired,
		Brief:       "DNS question name",
		Stability:   StabilityExperimental,
	})
	r.RegisterAttribute(&AttributeDefinition{
		Key:         DNSQuestionTypeKey,
		Type:        AttributeTypeString,
		Requirement: RequirementRecommended,
		Brief:       "DNS question type",
		Examples:    []string{"A", "AAAA", "CNAME", "MX"},
		Stability:   StabilityExperimental,
	})

	// Register network metrics
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricNetworkIO,
		Type:      MetricTypeCounter,
		Unit:      "By",
		Brief:     "Network bytes transferred",
		Stability: StabilityStable,
		Attributes: []string{
			NetworkIoDirectionKey,
			NetworkTransportKey,
			NetworkProtocolNameKey,
		},
	})
	r.RegisterMetric(&MetricDefinition{
		Name:      MetricNetworkConnections,
		Type:      MetricTypeUpDownCounter,
		Unit:      "{connection}",
		Brief:     "Number of network connections",
		Stability: StabilityStable,
		Attributes: []string{
			NetworkTransportKey,
			NetworkProtocolNameKey,
		},
	})
}

// NetworkAttributes provides a builder for network span attributes.
type NetworkAttributes struct {
	attrs []attribute.KeyValue
}

// NewNetworkAttributes creates a new network attributes builder.
func NewNetworkAttributes() *NetworkAttributes {
	return &NetworkAttributes{attrs: make([]attribute.KeyValue, 0, 12)}
}

// Transport sets the transport protocol.
func (n *NetworkAttributes) Transport(transport string) *NetworkAttributes {
	if transport != "" {
		n.attrs = append(n.attrs, attribute.String(NetworkTransportKey, transport))
	}
	return n
}

// Type sets the network type.
func (n *NetworkAttributes) Type(netType string) *NetworkAttributes {
	if netType != "" {
		n.attrs = append(n.attrs, attribute.String(NetworkTypeKey, netType))
	}
	return n
}

// ProtocolName sets the protocol name.
func (n *NetworkAttributes) ProtocolName(name string) *NetworkAttributes {
	if name != "" {
		n.attrs = append(n.attrs, attribute.String(NetworkProtocolNameKey, name))
	}
	return n
}

// ProtocolVersion sets the protocol version.
func (n *NetworkAttributes) ProtocolVersion(version string) *NetworkAttributes {
	if version != "" {
		n.attrs = append(n.attrs, attribute.String(NetworkProtocolVersionKey, version))
	}
	return n
}

// PeerAddress sets the peer address.
func (n *NetworkAttributes) PeerAddress(addr string) *NetworkAttributes {
	if addr != "" {
		n.attrs = append(n.attrs, attribute.String(NetworkPeerAddressKey, addr))
	}
	return n
}

// PeerPort sets the peer port.
func (n *NetworkAttributes) PeerPort(port int) *NetworkAttributes {
	n.attrs = append(n.attrs, attribute.Int(NetworkPeerPortKey, port))
	return n
}

// LocalAddress sets the local address.
func (n *NetworkAttributes) LocalAddress(addr string) *NetworkAttributes {
	if addr != "" {
		n.attrs = append(n.attrs, attribute.String(NetworkLocalAddressKey, addr))
	}
	return n
}

// LocalPort sets the local port.
func (n *NetworkAttributes) LocalPort(port int) *NetworkAttributes {
	n.attrs = append(n.attrs, attribute.Int(NetworkLocalPortKey, port))
	return n
}

// IODirection sets the IO direction.
func (n *NetworkAttributes) IODirection(direction string) *NetworkAttributes {
	if direction != "" {
		n.attrs = append(n.attrs, attribute.String(NetworkIoDirectionKey, direction))
	}
	return n
}

// Build returns the accumulated attributes.
func (n *NetworkAttributes) Build() []attribute.KeyValue {
	return n.attrs
}

// TLSAttributes provides a builder for TLS attributes.
type TLSAttributes struct {
	attrs []attribute.KeyValue
}

// NewTLSAttributes creates a new TLS attributes builder.
func NewTLSAttributes() *TLSAttributes {
	return &TLSAttributes{attrs: make([]attribute.KeyValue, 0, 8)}
}

// ProtocolName sets the TLS protocol name.
func (t *TLSAttributes) ProtocolName(name string) *TLSAttributes {
	if name != "" {
		t.attrs = append(t.attrs, attribute.String(TLSProtocolNameKey, name))
	}
	return t
}

// ProtocolVersion sets the TLS protocol version.
func (t *TLSAttributes) ProtocolVersion(version string) *TLSAttributes {
	if version != "" {
		t.attrs = append(t.attrs, attribute.String(TLSProtocolVersionKey, version))
	}
	return t
}

// Cipher sets the TLS cipher suite.
func (t *TLSAttributes) Cipher(cipher string) *TLSAttributes {
	if cipher != "" {
		t.attrs = append(t.attrs, attribute.String(TLSCipherKey, cipher))
	}
	return t
}

// ServerName sets the SNI server name.
func (t *TLSAttributes) ServerName(name string) *TLSAttributes {
	if name != "" {
		t.attrs = append(t.attrs, attribute.String(TLSClientServerNameKey, name))
	}
	return t
}

// Resumed sets whether the session was resumed.
func (t *TLSAttributes) Resumed(resumed bool) *TLSAttributes {
	t.attrs = append(t.attrs, attribute.Bool(TLSResumedKey, resumed))
	return t
}

// NextProtocol sets the ALPN negotiated protocol.
func (t *TLSAttributes) NextProtocol(protocol string) *TLSAttributes {
	if protocol != "" {
		t.attrs = append(t.attrs, attribute.String(TLSNextProtocolKey, protocol))
	}
	return t
}

// Build returns the accumulated attributes.
func (t *TLSAttributes) Build() []attribute.KeyValue {
	return t.attrs
}

// DNSAttributes provides a builder for DNS attributes.
type DNSAttributes struct {
	attrs []attribute.KeyValue
}

// NewDNSAttributes creates a new DNS attributes builder.
func NewDNSAttributes() *DNSAttributes {
	return &DNSAttributes{attrs: make([]attribute.KeyValue, 0, 8)}
}

// QuestionName sets the DNS question name.
func (d *DNSAttributes) QuestionName(name string) *DNSAttributes {
	if name != "" {
		d.attrs = append(d.attrs, attribute.String(DNSQuestionNameKey, name))
	}
	return d
}

// QuestionType sets the DNS question type.
func (d *DNSAttributes) QuestionType(qtype string) *DNSAttributes {
	if qtype != "" {
		d.attrs = append(d.attrs, attribute.String(DNSQuestionTypeKey, qtype))
	}
	return d
}

// AnswerName sets the DNS answer name.
func (d *DNSAttributes) AnswerName(name string) *DNSAttributes {
	if name != "" {
		d.attrs = append(d.attrs, attribute.String(DNSAnswerNameKey, name))
	}
	return d
}

// AnswerType sets the DNS answer type.
func (d *DNSAttributes) AnswerType(atype string) *DNSAttributes {
	if atype != "" {
		d.attrs = append(d.attrs, attribute.String(DNSAnswerTypeKey, atype))
	}
	return d
}

// AnswerRdata sets the DNS answer rdata.
func (d *DNSAttributes) AnswerRdata(rdata string) *DNSAttributes {
	if rdata != "" {
		d.attrs = append(d.attrs, attribute.String(DNSAnswerRdataKey, rdata))
	}
	return d
}

// Build returns the accumulated attributes.
func (d *DNSAttributes) Build() []attribute.KeyValue {
	return d.attrs
}

// Metric name constants for network
const (
	MetricNetworkIO          = "network.io"
	MetricNetworkConnections = "network.connections"
)
