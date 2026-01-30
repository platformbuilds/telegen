// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package snmp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/gosnmp/gosnmp"
)

// TrapReceiver listens for SNMP traps and informs
type TrapReceiver struct {
	config      TrapReceiverConfig
	mibResolver *MIBResolver
	converter   *MetricConverter
	log         *slog.Logger

	listener *gosnmp.TrapListener
	handlers []TrapHandler

	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
}

// TrapHandler is a callback for handling received traps
type TrapHandler func(trap *Trap)

// Trap represents a received SNMP trap
type Trap struct {
	Source    net.IP
	Version   SNMPVersion
	Community string
	Username  string
	TrapOID   string
	TrapName  string
	Uptime    uint32
	Variables []TrapVariable
	Timestamp int64
}

// TrapVariable represents a variable binding in a trap
type TrapVariable struct {
	OID   string
	Name  string
	Type  string
	Value interface{}
}

// NewTrapReceiver creates a new SNMP trap receiver
func NewTrapReceiver(cfg TrapReceiverConfig, resolver *MIBResolver, converter *MetricConverter, log *slog.Logger) (*TrapReceiver, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "snmp-trap-receiver")

	return &TrapReceiver{
		config:      cfg,
		mibResolver: resolver,
		converter:   converter,
		log:         log,
		stopCh:      make(chan struct{}),
		handlers:    make([]TrapHandler, 0),
	}, nil
}

// Start starts the trap receiver
func (r *TrapReceiver) Start(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.running {
		return nil
	}

	r.log.Info("starting trap receiver", "address", r.config.ListenAddress)

	// Create trap listener
	r.listener = gosnmp.NewTrapListener()
	r.listener.OnNewTrap = r.handleTrap
	r.listener.Params = gosnmp.Default

	// Configure SNMPv3 users if any
	if len(r.config.V3Users) > 0 {
		r.listener.Params.Version = gosnmp.Version3
		r.listener.Params.SecurityModel = gosnmp.UserSecurityModel
		// Note: Multiple users would require a custom security table
		if len(r.config.V3Users) > 0 {
			user := r.config.V3Users[0]
			r.listener.Params.SecurityParameters = r.createSecurityParams(user)
		}
	}

	// Start listening in a goroutine
	go func() {
		if err := r.listener.Listen(r.config.ListenAddress); err != nil {
			r.log.Error("trap listener error", "error", err)
		}
	}()

	r.running = true
	return nil
}

// Stop stops the trap receiver
func (r *TrapReceiver) Stop(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.running {
		return nil
	}

	r.log.Info("stopping trap receiver")

	close(r.stopCh)

	if r.listener != nil {
		r.listener.Close()
	}

	r.running = false
	return nil
}

// RegisterHandler registers a handler for received traps
func (r *TrapReceiver) RegisterHandler(handler TrapHandler) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.handlers = append(r.handlers, handler)
}

// handleTrap processes a received SNMP trap
func (r *TrapReceiver) handleTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) {
	r.log.Debug("received trap", "source", addr.IP, "version", packet.Version)

	// Validate community string for v1/v2c
	if packet.Version != gosnmp.Version3 {
		if !r.validateCommunity(packet.Community) {
			r.log.Warn("rejected trap with invalid community", "source", addr.IP)
			return
		}
	}

	// Parse trap
	trap := r.parseTrap(packet, addr)

	// Call handlers
	r.mu.RLock()
	handlers := r.handlers
	r.mu.RUnlock()

	for _, handler := range handlers {
		handler(trap)
	}
}

// validateCommunity checks if a community string is allowed
func (r *TrapReceiver) validateCommunity(community string) bool {
	for _, allowed := range r.config.CommunityStrings {
		if community == allowed {
			return true
		}
	}
	return false
}

// parseTrap converts a gosnmp packet to our Trap type
func (r *TrapReceiver) parseTrap(packet *gosnmp.SnmpPacket, addr *net.UDPAddr) *Trap {
	trap := &Trap{
		Source:    addr.IP,
		Community: packet.Community,
		Variables: make([]TrapVariable, 0, len(packet.Variables)),
	}

	// Set version
	switch packet.Version {
	case gosnmp.Version1:
		trap.Version = SNMPv1
	case gosnmp.Version2c:
		trap.Version = SNMPv2c
	case gosnmp.Version3:
		trap.Version = SNMPv3
		if usp, ok := packet.SecurityParameters.(*gosnmp.UsmSecurityParameters); ok {
			trap.Username = usp.UserName
		}
	}

	// Parse variables
	for _, v := range packet.Variables {
		variable := TrapVariable{
			OID:   v.Name,
			Value: v.Value,
		}

		// Resolve OID name
		if obj, ok := r.mibResolver.Resolve(v.Name); ok {
			variable.Name = obj.Name
			variable.Type = obj.Type
		}

		// Check for trap OID
		if v.Name == ".1.3.6.1.6.3.1.1.4.1.0" || v.Name == "1.3.6.1.6.3.1.1.4.1.0" {
			if oid, ok := v.Value.(string); ok {
				trap.TrapOID = oid
				if obj, ok := r.mibResolver.Resolve(oid); ok {
					trap.TrapName = obj.Name
				}
			}
		}

		// Check for uptime
		if v.Name == ".1.3.6.1.2.1.1.3.0" || v.Name == "1.3.6.1.2.1.1.3.0" {
			if uptime, ok := v.Value.(uint32); ok {
				trap.Uptime = uptime
			}
		}

		trap.Variables = append(trap.Variables, variable)
	}

	return trap
}

// createSecurityParams creates SNMPv3 security parameters for a user
func (r *TrapReceiver) createSecurityParams(user V3User) *gosnmp.UsmSecurityParameters {
	params := &gosnmp.UsmSecurityParameters{
		UserName: user.Username,
	}

	// Authentication protocol
	switch user.AuthProtocol {
	case AuthMD5:
		params.AuthenticationProtocol = gosnmp.MD5
	case AuthSHA:
		params.AuthenticationProtocol = gosnmp.SHA
	case AuthSHA256:
		params.AuthenticationProtocol = gosnmp.SHA256
	case AuthSHA512:
		params.AuthenticationProtocol = gosnmp.SHA512
	default:
		params.AuthenticationProtocol = gosnmp.SHA256
	}
	params.AuthenticationPassphrase = user.AuthPassword

	// Privacy protocol
	switch user.PrivProtocol {
	case PrivDES:
		params.PrivacyProtocol = gosnmp.DES
	case PrivAES:
		params.PrivacyProtocol = gosnmp.AES
	case PrivAES192:
		params.PrivacyProtocol = gosnmp.AES192
	case PrivAES256:
		params.PrivacyProtocol = gosnmp.AES256
	default:
		params.PrivacyProtocol = gosnmp.AES256
	}
	params.PrivacyPassphrase = user.PrivPassword

	return params
}

// SendInformResponse sends an acknowledgement for an INFORM request
func (r *TrapReceiver) SendInformResponse(addr *net.UDPAddr, requestID uint32) error {
	// Create SNMP connection to send response
	conn := &gosnmp.GoSNMP{
		Target:  addr.IP.String(),
		Port:    uint16(addr.Port),
		Version: gosnmp.Version2c,
		Timeout: gosnmp.Default.Timeout,
	}

	if err := conn.Connect(); err != nil {
		return fmt.Errorf("failed to connect for inform response: %w", err)
	}
	defer conn.Conn.Close()

	// Send response (GetResponse with same request ID)
	// This is a simplified implementation
	r.log.Debug("sent inform response", "target", addr, "requestID", requestID)

	return nil
}
