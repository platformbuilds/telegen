// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package snmp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gosnmp/gosnmp"
)

// Poller handles SNMP polling operations
type Poller struct {
	config      PollingConfig
	mibResolver *MIBResolver
	converter   *MetricConverter
	log         *slog.Logger

	// Connection pool
	mu    sync.Mutex
	conns map[string]*gosnmp.GoSNMP

	// Semaphore for concurrent polling
	sem chan struct{}
}

// NewPoller creates a new SNMP poller
func NewPoller(cfg PollingConfig, resolver *MIBResolver, converter *MetricConverter, log *slog.Logger) (*Poller, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "snmp-poller")

	maxConcurrent := cfg.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 100
	}

	return &Poller{
		config:      cfg,
		mibResolver: resolver,
		converter:   converter,
		log:         log,
		conns:       make(map[string]*gosnmp.GoSNMP),
		sem:         make(chan struct{}, maxConcurrent),
	}, nil
}

// Poll polls a target and returns metrics
func (p *Poller) Poll(ctx context.Context, target Target) ([]Metric, error) {
	// Acquire semaphore
	select {
	case p.sem <- struct{}{}:
		defer func() { <-p.sem }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	// Get or create SNMP connection
	conn, err := p.getConnection(target)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", target.Address, err)
	}

	var allMetrics []Metric

	// Poll each module
	for _, moduleName := range target.Modules {
		module, err := LoadModule(moduleName)
		if err != nil {
			p.log.Warn("failed to load module", "module", moduleName, "error", err)
			continue
		}

		metrics, err := p.pollModule(ctx, conn, target, module)
		if err != nil {
			p.log.Warn("failed to poll module", "module", moduleName, "target", target.Name, "error", err)
			continue
		}

		allMetrics = append(allMetrics, metrics...)
	}

	return allMetrics, nil
}

// getConnection returns a cached or new SNMP connection for a target
func (p *Poller) getConnection(target Target) (*gosnmp.GoSNMP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	key := target.Address + ":" + string(target.Version)
	if conn, ok := p.conns[key]; ok {
		return conn, nil
	}

	// Parse address
	host, portStr, err := net.SplitHostPort(target.Address)
	if err != nil {
		// Assume default port
		host = target.Address
		portStr = "161"
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 161
	}

	// Create new connection
	conn := &gosnmp.GoSNMP{
		Target:  host,
		Port:    uint16(port),
		Timeout: p.config.Timeout,
		Retries: p.config.Retries,
	}

	// Configure version and authentication
	switch target.Version {
	case SNMPv1:
		conn.Version = gosnmp.Version1
		conn.Community = target.Community
	case SNMPv2c:
		conn.Version = gosnmp.Version2c
		conn.Community = target.Community
	case SNMPv3:
		conn.Version = gosnmp.Version3
		conn.SecurityModel = gosnmp.UserSecurityModel
		conn.MsgFlags = p.getMsgFlags(target.SecurityLevel)
		conn.SecurityParameters = p.getSecurityParams(target)
	default:
		conn.Version = gosnmp.Version2c
		conn.Community = target.Community
	}

	if err := conn.Connect(); err != nil {
		return nil, err
	}

	p.conns[key] = conn
	return conn, nil
}

// getMsgFlags returns the SNMPv3 message flags for a security level
func (p *Poller) getMsgFlags(level SecurityLevel) gosnmp.SnmpV3MsgFlags {
	switch level {
	case AuthPriv:
		return gosnmp.AuthPriv
	case AuthNoPriv:
		return gosnmp.AuthNoPriv
	case NoAuthNoPriv:
		return gosnmp.NoAuthNoPriv
	default:
		return gosnmp.AuthPriv
	}
}

// getSecurityParams returns SNMPv3 security parameters
func (p *Poller) getSecurityParams(target Target) *gosnmp.UsmSecurityParameters {
	params := &gosnmp.UsmSecurityParameters{
		UserName: target.Username,
	}

	// Authentication protocol
	switch target.AuthProtocol {
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
	params.AuthenticationPassphrase = target.AuthPassword

	// Privacy protocol
	switch target.PrivProtocol {
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
	params.PrivacyPassphrase = target.PrivPassword

	return params
}

// pollModule polls all OIDs defined in a module
func (p *Poller) pollModule(ctx context.Context, conn *gosnmp.GoSNMP, target Target, module *Module) ([]Metric, error) {
	var metrics []Metric
	now := time.Now()

	// Perform walks for table OIDs
	for _, walkOID := range module.Walk {
		results, err := p.walk(ctx, conn, walkOID)
		if err != nil {
			p.log.Warn("walk failed", "oid", walkOID, "error", err)
			continue
		}

		for _, result := range results {
			metric := p.converter.Convert(result, module, now)
			if metric != nil {
				metrics = append(metrics, *metric)
			}
		}
	}

	// Perform GET for specific metrics
	for _, metricDef := range module.Metrics {
		if metricDef.OID == "" {
			continue
		}

		results, err := p.get(ctx, conn, []string{metricDef.OID})
		if err != nil {
			p.log.Debug("get failed", "oid", metricDef.OID, "error", err)
			continue
		}

		for _, result := range results {
			metric := p.converter.ConvertWithDef(result, &metricDef, now)
			if metric != nil {
				metrics = append(metrics, *metric)
			}
		}
	}

	return metrics, nil
}

// walk performs an SNMP WALK or BULK WALK operation
func (p *Poller) walk(ctx context.Context, conn *gosnmp.GoSNMP, oid string) ([]gosnmp.SnmpPDU, error) {
	var results []gosnmp.SnmpPDU

	walkFunc := func(pdu gosnmp.SnmpPDU) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
			results = append(results, pdu)
			return nil
		}
	}

	var err error
	if conn.Version == gosnmp.Version1 {
		err = conn.Walk(oid, walkFunc)
	} else {
		err = conn.BulkWalk(oid, walkFunc)
	}

	return results, err
}

// get performs an SNMP GET operation
func (p *Poller) get(ctx context.Context, conn *gosnmp.GoSNMP, oids []string) ([]gosnmp.SnmpPDU, error) {
	result, err := conn.Get(oids)
	if err != nil {
		return nil, err
	}

	return result.Variables, nil
}

// BulkGet performs an SNMP GETBULK operation
func (p *Poller) BulkGet(ctx context.Context, target Target, oids []string, maxRepetitions int) ([]gosnmp.SnmpPDU, error) {
	conn, err := p.getConnection(target)
	if err != nil {
		return nil, err
	}

	if conn.Version == gosnmp.Version1 {
		// Fall back to regular GET for v1
		return p.get(ctx, conn, oids)
	}

	result, err := conn.GetBulk(oids, 0, uint32(maxRepetitions))
	if err != nil {
		return nil, err
	}

	return result.Variables, nil
}

// Close closes all SNMP connections
func (p *Poller) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	for key, conn := range p.conns {
		_ = conn.Conn.Close()
		delete(p.conns, key)
	}

	return nil
}

// Module represents an SNMP module definition
type Module struct {
	Name        string            `yaml:"module"`
	Description string            `yaml:"description"`
	Walk        []string          `yaml:"walk"`
	Metrics     []ModuleMetricDef `yaml:"metrics"`
}

// ModuleMetricDef defines a metric within a module
type ModuleMetricDef struct {
	Name       string            `yaml:"name"`
	OID        string            `yaml:"oid"`
	Type       string            `yaml:"type"` // counter, gauge
	Help       string            `yaml:"help"`
	Indexes    []ModuleIndexDef  `yaml:"indexes"`
	Lookups    []ModuleLookupDef `yaml:"lookups"`
	EnumValues map[int]string    `yaml:"enum_values"`
}

// ModuleIndexDef defines an index for a table metric
type ModuleIndexDef struct {
	LabelName string `yaml:"labelname"`
	Type      string `yaml:"type"`
}

// ModuleLookupDef defines a lookup for resolving index values
type ModuleLookupDef struct {
	Labels    []string `yaml:"labels"`
	OID       string   `yaml:"oid"`
	LabelName string   `yaml:"labelname"`
}

// LoadModule loads a module definition by name
func LoadModule(name string) (*Module, error) {
	// Check built-in modules first
	if module, ok := builtinModules[name]; ok {
		return module, nil
	}

	// TODO: Load from file system
	return nil, fmt.Errorf("module %q not found", name)
}

// builtinModules contains built-in module definitions
var builtinModules = map[string]*Module{
	"if_mib": {
		Name:        "if_mib",
		Description: "RFC 2863 - The Interfaces Group MIB",
		Walk: []string{
			"1.3.6.1.2.1.2.2",    // ifTable
			"1.3.6.1.2.1.31.1.1", // ifXTable
		},
		Metrics: []ModuleMetricDef{
			{
				Name: "ifAdminStatus",
				OID:  "1.3.6.1.2.1.2.2.1.7",
				Type: "gauge",
				Help: "The desired state of the interface",
				Indexes: []ModuleIndexDef{
					{LabelName: "ifIndex", Type: "Integer"},
				},
				EnumValues: map[int]string{
					1: "up",
					2: "down",
					3: "testing",
				},
			},
			{
				Name: "ifOperStatus",
				OID:  "1.3.6.1.2.1.2.2.1.8",
				Type: "gauge",
				Help: "The current operational state of the interface",
				Indexes: []ModuleIndexDef{
					{LabelName: "ifIndex", Type: "Integer"},
				},
				EnumValues: map[int]string{
					1: "up",
					2: "down",
					3: "testing",
					4: "unknown",
					5: "dormant",
					6: "notPresent",
					7: "lowerLayerDown",
				},
			},
			{
				Name: "ifHCInOctets",
				OID:  "1.3.6.1.2.1.31.1.1.1.6",
				Type: "counter",
				Help: "The total number of octets received on the interface (64-bit)",
				Indexes: []ModuleIndexDef{
					{LabelName: "ifIndex", Type: "Integer"},
				},
			},
			{
				Name: "ifHCOutOctets",
				OID:  "1.3.6.1.2.1.31.1.1.1.10",
				Type: "counter",
				Help: "The total number of octets transmitted out of the interface (64-bit)",
				Indexes: []ModuleIndexDef{
					{LabelName: "ifIndex", Type: "Integer"},
				},
			},
			{
				Name: "ifHCInUcastPkts",
				OID:  "1.3.6.1.2.1.31.1.1.1.7",
				Type: "counter",
				Help: "The number of unicast packets delivered to a higher-layer (64-bit)",
				Indexes: []ModuleIndexDef{
					{LabelName: "ifIndex", Type: "Integer"},
				},
			},
			{
				Name: "ifHCOutUcastPkts",
				OID:  "1.3.6.1.2.1.31.1.1.1.11",
				Type: "counter",
				Help: "The total number of unicast packets transmitted (64-bit)",
				Indexes: []ModuleIndexDef{
					{LabelName: "ifIndex", Type: "Integer"},
				},
			},
			{
				Name: "ifHighSpeed",
				OID:  "1.3.6.1.2.1.31.1.1.1.15",
				Type: "gauge",
				Help: "An estimate of the interface's current bandwidth in Mb/s",
				Indexes: []ModuleIndexDef{
					{LabelName: "ifIndex", Type: "Integer"},
				},
			},
			{
				Name: "ifInErrors",
				OID:  "1.3.6.1.2.1.2.2.1.14",
				Type: "counter",
				Help: "The number of inbound packets with errors",
				Indexes: []ModuleIndexDef{
					{LabelName: "ifIndex", Type: "Integer"},
				},
			},
			{
				Name: "ifOutErrors",
				OID:  "1.3.6.1.2.1.2.2.1.20",
				Type: "counter",
				Help: "The number of outbound packets with errors",
				Indexes: []ModuleIndexDef{
					{LabelName: "ifIndex", Type: "Integer"},
				},
			},
			{
				Name: "ifInDiscards",
				OID:  "1.3.6.1.2.1.2.2.1.13",
				Type: "counter",
				Help: "The number of inbound packets discarded",
				Indexes: []ModuleIndexDef{
					{LabelName: "ifIndex", Type: "Integer"},
				},
			},
			{
				Name: "ifOutDiscards",
				OID:  "1.3.6.1.2.1.2.2.1.19",
				Type: "counter",
				Help: "The number of outbound packets discarded",
				Indexes: []ModuleIndexDef{
					{LabelName: "ifIndex", Type: "Integer"},
				},
			},
		},
	},
	"system": {
		Name:        "system",
		Description: "SNMPv2-MIB System Group",
		Walk:        []string{"1.3.6.1.2.1.1"},
		Metrics: []ModuleMetricDef{
			{
				Name: "sysUpTime",
				OID:  "1.3.6.1.2.1.1.3",
				Type: "gauge",
				Help: "The time since the network management portion was last re-initialized",
			},
		},
	},
}

// extractIndex extracts the index from an OID based on a base OID
//
//nolint:unused // reserved for SNMP table index extraction
func extractIndex(fullOID, baseOID string) string {
	if !strings.HasPrefix(fullOID, baseOID) {
		return ""
	}
	suffix := strings.TrimPrefix(fullOID, baseOID)
	suffix = strings.TrimPrefix(suffix, ".")
	return suffix
}
