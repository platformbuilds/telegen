// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package snmp

import (
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/gosnmp/gosnmp"
)

// MetricType represents the type of a metric
type MetricType string

const (
	MetricTypeCounter MetricType = "counter"
	MetricTypeGauge   MetricType = "gauge"
	MetricTypeInfo    MetricType = "info"
	MetricTypeUnknown MetricType = "unknown"
)

// Metric represents a collected SNMP metric
type Metric struct {
	Name        string
	Help        string
	Type        MetricType
	Value       float64
	StringValue string
	Labels      map[string]string
	Timestamp   time.Time
	OID         string
}

// MetricConverter converts SNMP values to OpenMetrics format
type MetricConverter struct {
	mibResolver *MIBResolver
	log         *slog.Logger

	// Lookup cache for index resolution
	lookupCache map[string]map[string]string // OID -> index -> value
}

// NewMetricConverter creates a new metric converter
func NewMetricConverter(resolver *MIBResolver, log *slog.Logger) *MetricConverter {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "metric-converter")

	return &MetricConverter{
		mibResolver: resolver,
		log:         log,
		lookupCache: make(map[string]map[string]string),
	}
}

// Convert converts an SNMP PDU to a Metric using MIB information
func (c *MetricConverter) Convert(pdu gosnmp.SnmpPDU, module *Module, timestamp time.Time) *Metric {
	// Find matching metric definition in module
	for _, metricDef := range module.Metrics {
		if strings.HasPrefix(pdu.Name, metricDef.OID) || strings.HasPrefix(pdu.Name, "."+metricDef.OID) {
			return c.ConvertWithDef(pdu, &metricDef, timestamp)
		}
	}

	// Fall back to MIB resolution
	return c.convertWithMIB(pdu, timestamp)
}

// ConvertWithDef converts an SNMP PDU using a specific metric definition
func (c *MetricConverter) ConvertWithDef(pdu gosnmp.SnmpPDU, def *ModuleMetricDef, timestamp time.Time) *Metric {
	value, stringValue := c.extractValue(pdu)

	metric := &Metric{
		Name:        c.sanitizeMetricName(def.Name),
		Help:        def.Help,
		Type:        c.parseMetricType(def.Type),
		Value:       value,
		StringValue: stringValue,
		Labels:      make(map[string]string),
		Timestamp:   timestamp,
		OID:         pdu.Name,
	}

	// Extract index from OID
	baseOID := def.OID
	if !strings.HasPrefix(baseOID, ".") {
		baseOID = "." + baseOID
	}
	oid := pdu.Name
	if !strings.HasPrefix(oid, ".") {
		oid = "." + oid
	}

	if strings.HasPrefix(oid, baseOID) {
		suffix := strings.TrimPrefix(oid, baseOID)
		suffix = strings.TrimPrefix(suffix, ".")

		// Parse index labels
		if len(def.Indexes) > 0 && suffix != "" {
			parts := strings.Split(suffix, ".")
			for i, idx := range def.Indexes {
				if i < len(parts) {
					metric.Labels[idx.LabelName] = parts[i]
				}
			}
		}
	}

	// Resolve enum values
	if def.EnumValues != nil {
		if intVal, ok := pdu.Value.(int); ok {
			if enumStr, ok := def.EnumValues[intVal]; ok {
				metric.Labels[def.Name+"_label"] = enumStr
			}
		}
	}

	return metric
}

// convertWithMIB converts a PDU using MIB information
func (c *MetricConverter) convertWithMIB(pdu gosnmp.SnmpPDU, timestamp time.Time) *Metric {
	value, stringValue := c.extractValue(pdu)

	metric := &Metric{
		Value:       value,
		StringValue: stringValue,
		Labels:      make(map[string]string),
		Timestamp:   timestamp,
		OID:         pdu.Name,
		Type:        MetricTypeGauge,
	}

	// Try to resolve OID
	oid := strings.TrimPrefix(pdu.Name, ".")

	if obj, ok := c.mibResolver.Resolve(oid); ok {
		metric.Name = c.sanitizeMetricName(obj.Name)
		metric.Help = obj.Description
		metric.Type = c.mibTypeToMetricType(obj.Type)

		// Extract index from resolved name
		if idx := strings.LastIndex(obj.Name, "."); idx > 0 {
			baseName := obj.Name[:idx]
			index := obj.Name[idx+1:]
			metric.Name = c.sanitizeMetricName(baseName)
			metric.Labels["index"] = index
		}

		// Resolve enum value
		if obj.EnumValues != nil {
			if intVal, ok := pdu.Value.(int); ok {
				if enumStr, ok := obj.EnumValues[intVal]; ok {
					metric.Labels["value_label"] = enumStr
				}
			}
		}
	} else {
		// Use OID as name
		metric.Name = "snmp_" + strings.ReplaceAll(oid, ".", "_")
	}

	return metric
}

// extractValue extracts the numeric and string value from a PDU
func (c *MetricConverter) extractValue(pdu gosnmp.SnmpPDU) (float64, string) {
	switch pdu.Type {
	case gosnmp.Counter32:
		return float64(gosnmp.ToBigInt(pdu.Value).Uint64()), ""
	case gosnmp.Counter64:
		return float64(gosnmp.ToBigInt(pdu.Value).Uint64()), ""
	case gosnmp.Gauge32:
		return float64(gosnmp.ToBigInt(pdu.Value).Uint64()), ""
	case gosnmp.Integer:
		return float64(gosnmp.ToBigInt(pdu.Value).Int64()), ""
	case gosnmp.TimeTicks:
		return float64(gosnmp.ToBigInt(pdu.Value).Uint64()) / 100.0, "" // Convert to seconds
	case gosnmp.OctetString:
		if bytes, ok := pdu.Value.([]byte); ok {
			str := string(bytes)
			// Try to parse as number
			if f, err := strconv.ParseFloat(str, 64); err == nil {
				return f, str
			}
			return 0, str
		}
		return 0, ""
	case gosnmp.IPAddress:
		if ip, ok := pdu.Value.(string); ok {
			return 0, ip
		}
		return 0, ""
	case gosnmp.ObjectIdentifier:
		if oid, ok := pdu.Value.(string); ok {
			return 0, oid
		}
		return 0, ""
	case gosnmp.Null:
		return 0, ""
	case gosnmp.NoSuchObject, gosnmp.NoSuchInstance, gosnmp.EndOfMibView:
		return 0, ""
	default:
		// Try to convert to big int
		bi := gosnmp.ToBigInt(pdu.Value)
		return float64(bi.Int64()), ""
	}
}

// sanitizeMetricName converts an SNMP name to a valid Prometheus metric name
func (c *MetricConverter) sanitizeMetricName(name string) string {
	// Convert to lowercase and replace invalid characters
	result := strings.Builder{}
	result.WriteString("snmp_")

	for i, ch := range name {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9' && i > 0) || ch == '_' {
			result.WriteRune(ch)
		} else if ch == '-' || ch == '.' || ch == ' ' {
			result.WriteRune('_')
		}
	}

	return strings.ToLower(result.String())
}

// parseMetricType parses a metric type string
func (c *MetricConverter) parseMetricType(typeStr string) MetricType {
	switch strings.ToLower(typeStr) {
	case "counter":
		return MetricTypeCounter
	case "gauge":
		return MetricTypeGauge
	case "info":
		return MetricTypeInfo
	default:
		return MetricTypeUnknown
	}
}

// mibTypeToMetricType converts a MIB SYNTAX type to a metric type
func (c *MetricConverter) mibTypeToMetricType(mibType string) MetricType {
	switch mibType {
	case "counter", "counter64":
		return MetricTypeCounter
	case "gauge", "integer", "timeticks":
		return MetricTypeGauge
	case "string", "ipaddress", "oid":
		return MetricTypeInfo
	default:
		return MetricTypeGauge
	}
}

// UpdateLookupCache updates the lookup cache with values for index resolution
func (c *MetricConverter) UpdateLookupCache(oid string, index string, value string) {
	if _, ok := c.lookupCache[oid]; !ok {
		c.lookupCache[oid] = make(map[string]string)
	}
	c.lookupCache[oid][index] = value
}

// ResolveLookup resolves an index to its lookup value
func (c *MetricConverter) ResolveLookup(oid string, index string) (string, bool) {
	if cache, ok := c.lookupCache[oid]; ok {
		if value, ok := cache[index]; ok {
			return value, true
		}
	}
	return "", false
}

// ClearLookupCache clears the lookup cache
func (c *MetricConverter) ClearLookupCache() {
	c.lookupCache = make(map[string]map[string]string)
}
