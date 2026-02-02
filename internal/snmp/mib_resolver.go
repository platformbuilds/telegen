// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package snmp

import (
	"bufio"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// MIBObject represents a single object defined in a MIB
type MIBObject struct {
	OID         string
	Name        string
	Module      string
	Type        string
	Syntax      string
	Access      string
	Status      string
	Description string
	EnumValues  map[int]string
	Parent      string
	Index       []string
}

// MIBModule represents a loaded MIB module
type MIBModule struct {
	Name    string
	File    string
	Imports map[string][]string // module -> imported symbols
	Objects map[string]*MIBObject
	Loaded  bool
}

// MIBResolver resolves OIDs to human-readable names and vice versa
type MIBResolver struct {
	config MIBConfig
	log    *slog.Logger

	mu        sync.RWMutex
	oidToName map[string]*MIBObject
	nameToOID map[string]string
	modules   map[string]*MIBModule

	// Standard OID prefixes
	standardPrefixes map[string]string
}

// NewMIBResolver creates a new MIB resolver
func NewMIBResolver(cfg MIBConfig, log *slog.Logger) (*MIBResolver, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "mib-resolver")

	r := &MIBResolver{
		config:    cfg,
		log:       log,
		oidToName: make(map[string]*MIBObject),
		nameToOID: make(map[string]string),
		modules:   make(map[string]*MIBModule),
	}

	// Initialize standard OID prefixes
	r.initStandardPrefixes()

	return r, nil
}

// initStandardPrefixes sets up well-known OID prefixes
func (r *MIBResolver) initStandardPrefixes() {
	r.standardPrefixes = map[string]string{
		"1.3.6.1":                 "internet",
		"1.3.6.1.1":               "directory",
		"1.3.6.1.2":               "mgmt",
		"1.3.6.1.2.1":             "mib-2",
		"1.3.6.1.2.1.1":           "system",
		"1.3.6.1.2.1.1.1":         "sysDescr",
		"1.3.6.1.2.1.1.2":         "sysObjectID",
		"1.3.6.1.2.1.1.3":         "sysUpTime",
		"1.3.6.1.2.1.1.4":         "sysContact",
		"1.3.6.1.2.1.1.5":         "sysName",
		"1.3.6.1.2.1.1.6":         "sysLocation",
		"1.3.6.1.2.1.1.7":         "sysServices",
		"1.3.6.1.2.1.2":           "interfaces",
		"1.3.6.1.2.1.2.1":         "ifNumber",
		"1.3.6.1.2.1.2.2":         "ifTable",
		"1.3.6.1.2.1.2.2.1":       "ifEntry",
		"1.3.6.1.2.1.2.2.1.1":     "ifIndex",
		"1.3.6.1.2.1.2.2.1.2":     "ifDescr",
		"1.3.6.1.2.1.2.2.1.3":     "ifType",
		"1.3.6.1.2.1.2.2.1.4":     "ifMtu",
		"1.3.6.1.2.1.2.2.1.5":     "ifSpeed",
		"1.3.6.1.2.1.2.2.1.6":     "ifPhysAddress",
		"1.3.6.1.2.1.2.2.1.7":     "ifAdminStatus",
		"1.3.6.1.2.1.2.2.1.8":     "ifOperStatus",
		"1.3.6.1.2.1.2.2.1.9":     "ifLastChange",
		"1.3.6.1.2.1.2.2.1.10":    "ifInOctets",
		"1.3.6.1.2.1.2.2.1.11":    "ifInUcastPkts",
		"1.3.6.1.2.1.2.2.1.12":    "ifInNUcastPkts",
		"1.3.6.1.2.1.2.2.1.13":    "ifInDiscards",
		"1.3.6.1.2.1.2.2.1.14":    "ifInErrors",
		"1.3.6.1.2.1.2.2.1.15":    "ifInUnknownProtos",
		"1.3.6.1.2.1.2.2.1.16":    "ifOutOctets",
		"1.3.6.1.2.1.2.2.1.17":    "ifOutUcastPkts",
		"1.3.6.1.2.1.2.2.1.18":    "ifOutNUcastPkts",
		"1.3.6.1.2.1.2.2.1.19":    "ifOutDiscards",
		"1.3.6.1.2.1.2.2.1.20":    "ifOutErrors",
		"1.3.6.1.2.1.2.2.1.21":    "ifOutQLen",
		"1.3.6.1.2.1.2.2.1.22":    "ifSpecific",
		"1.3.6.1.2.1.31":          "ifMIB",
		"1.3.6.1.2.1.31.1":        "ifMIBObjects",
		"1.3.6.1.2.1.31.1.1":      "ifXTable",
		"1.3.6.1.2.1.31.1.1.1":    "ifXEntry",
		"1.3.6.1.2.1.31.1.1.1.1":  "ifName",
		"1.3.6.1.2.1.31.1.1.1.6":  "ifHCInOctets",
		"1.3.6.1.2.1.31.1.1.1.7":  "ifHCInUcastPkts",
		"1.3.6.1.2.1.31.1.1.1.8":  "ifHCInMulticastPkts",
		"1.3.6.1.2.1.31.1.1.1.9":  "ifHCInBroadcastPkts",
		"1.3.6.1.2.1.31.1.1.1.10": "ifHCOutOctets",
		"1.3.6.1.2.1.31.1.1.1.11": "ifHCOutUcastPkts",
		"1.3.6.1.2.1.31.1.1.1.12": "ifHCOutMulticastPkts",
		"1.3.6.1.2.1.31.1.1.1.13": "ifHCOutBroadcastPkts",
		"1.3.6.1.2.1.31.1.1.1.15": "ifHighSpeed",
		"1.3.6.1.2.1.31.1.1.1.18": "ifAlias",
		"1.3.6.1.4":               "private",
		"1.3.6.1.4.1":             "enterprises",
		"1.3.6.1.6":               "snmpV2",
		"1.3.6.1.6.3":             "snmpModules",
		"1.3.6.1.6.3.1":           "snmpMIB",
		"1.3.6.1.6.3.1.1.4":       "snmpTrap",
		"1.3.6.1.6.3.1.1.4.1":     "snmpTrapOID",
	}

	// Add standard prefixes to resolver
	for oid, name := range r.standardPrefixes {
		r.oidToName[oid] = &MIBObject{
			OID:    oid,
			Name:   name,
			Module: "SNMPv2-MIB",
		}
		r.nameToOID[name] = oid
	}
}

// LoadMIBs loads MIB files from the specified search paths
func (r *MIBResolver) LoadMIBs(searchPaths []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var loadErrors []error

	for _, path := range searchPaths {
		if err := r.loadMIBsFromPath(path); err != nil {
			loadErrors = append(loadErrors, fmt.Errorf("path %s: %w", path, err))
		}
	}

	r.log.Info("MIBs loaded",
		"objects", len(r.oidToName),
		"modules", len(r.modules),
		"errors", len(loadErrors))

	if len(loadErrors) > 0 {
		return fmt.Errorf("some MIBs failed to load: %v", loadErrors)
	}

	return nil
}

// loadMIBsFromPath loads all MIB files from a directory
func (r *MIBResolver) loadMIBsFromPath(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			r.log.Debug("MIB path does not exist", "path", path)
			return nil
		}
		return err
	}

	if !info.IsDir() {
		return r.loadMIBFile(path)
	}

	entries, err := os.ReadDir(path)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.HasSuffix(name, ".mib") ||
			strings.HasSuffix(name, ".txt") ||
			strings.HasSuffix(name, ".my") ||
			!strings.Contains(name, ".") {
			if err := r.loadMIBFile(filepath.Join(path, name)); err != nil {
				r.log.Debug("failed to load MIB file", "file", name, "error", err)
			}
		}
	}

	return nil
}

// loadMIBFile parses and loads a single MIB file
func (r *MIBResolver) loadMIBFile(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	module := &MIBModule{
		File:    path,
		Imports: make(map[string][]string),
		Objects: make(map[string]*MIBObject),
	}

	scanner := bufio.NewScanner(file)
	var currentObject *MIBObject
	var inDescription bool
	var descriptionBuilder strings.Builder

	// Regex patterns for parsing
	moduleDefRe := regexp.MustCompile(`^(\S+)\s+DEFINITIONS\s*::=\s*BEGIN`)
	objectTypeRe := regexp.MustCompile(`^(\S+)\s+OBJECT-TYPE`)
	objectIdentityRe := regexp.MustCompile(`^(\S+)\s+OBJECT-IDENTITY`)
	objectIdentifierRe := regexp.MustCompile(`^(\S+)\s+OBJECT\s+IDENTIFIER\s*::=\s*\{\s*(\S+)\s+(\d+)\s*\}`)
	syntaxRe := regexp.MustCompile(`^\s*SYNTAX\s+(.+)`)
	accessRe := regexp.MustCompile(`^\s*(?:MAX-)?ACCESS\s+(\S+)`)
	statusRe := regexp.MustCompile(`^\s*STATUS\s+(\S+)`)
	descriptionStartRe := regexp.MustCompile(`^\s*DESCRIPTION\s*"(.*)`)
	assignmentRe := regexp.MustCompile(`::=\s*\{\s*(\S+)\s+(\d+)\s*\}`)

	for scanner.Scan() {
		line := scanner.Text()

		// Check for module definition
		if matches := moduleDefRe.FindStringSubmatch(line); matches != nil {
			module.Name = matches[1]
			continue
		}

		// Handle multi-line description
		if inDescription {
			if idx := strings.Index(line, `"`); idx >= 0 {
				descriptionBuilder.WriteString(line[:idx])
				if currentObject != nil {
					currentObject.Description = descriptionBuilder.String()
				}
				inDescription = false
				descriptionBuilder.Reset()
			} else {
				descriptionBuilder.WriteString(line)
				descriptionBuilder.WriteString("\n")
			}
			continue
		}

		// Check for OBJECT-TYPE definition
		if matches := objectTypeRe.FindStringSubmatch(line); matches != nil {
			currentObject = &MIBObject{
				Name:       matches[1],
				Module:     module.Name,
				EnumValues: make(map[int]string),
			}
			continue
		}

		// Check for OBJECT-IDENTITY definition
		if matches := objectIdentityRe.FindStringSubmatch(line); matches != nil {
			currentObject = &MIBObject{
				Name:       matches[1],
				Module:     module.Name,
				EnumValues: make(map[int]string),
			}
			continue
		}

		// Check for simple OBJECT IDENTIFIER assignment
		if matches := objectIdentifierRe.FindStringSubmatch(line); matches != nil {
			name := matches[1]
			parent := matches[2]
			index := matches[3]

			parentOID := r.resolveParentOID(parent)
			if parentOID != "" {
				oid := parentOID + "." + index
				obj := &MIBObject{
					OID:    oid,
					Name:   name,
					Module: module.Name,
					Parent: parent,
				}
				module.Objects[name] = obj
				r.oidToName[oid] = obj
				r.nameToOID[name] = oid
			}
			continue
		}

		if currentObject != nil {
			// Check for SYNTAX
			if matches := syntaxRe.FindStringSubmatch(line); matches != nil {
				currentObject.Syntax = strings.TrimSpace(matches[1])
				currentObject.Type = r.syntaxToType(currentObject.Syntax)
				continue
			}

			// Check for ACCESS
			if matches := accessRe.FindStringSubmatch(line); matches != nil {
				currentObject.Access = matches[1]
				continue
			}

			// Check for STATUS
			if matches := statusRe.FindStringSubmatch(line); matches != nil {
				currentObject.Status = matches[1]
				continue
			}

			// Check for DESCRIPTION start
			if matches := descriptionStartRe.FindStringSubmatch(line); matches != nil {
				desc := matches[1]
				if idx := strings.Index(desc, `"`); idx >= 0 {
					currentObject.Description = desc[:idx]
				} else {
					descriptionBuilder.WriteString(desc)
					inDescription = true
				}
				continue
			}

			// Check for assignment (end of object definition)
			if matches := assignmentRe.FindStringSubmatch(line); matches != nil {
				parent := matches[1]
				index := matches[2]

				parentOID := r.resolveParentOID(parent)
				if parentOID != "" {
					currentObject.OID = parentOID + "." + index
					currentObject.Parent = parent
					module.Objects[currentObject.Name] = currentObject
					r.oidToName[currentObject.OID] = currentObject
					r.nameToOID[currentObject.Name] = currentObject.OID
				}
				currentObject = nil
			}
		}
	}

	if module.Name != "" {
		module.Loaded = true
		r.modules[module.Name] = module
		r.log.Debug("loaded MIB module", "name", module.Name, "objects", len(module.Objects))
	}

	return scanner.Err()
}

// resolveParentOID resolves a parent name to its OID
func (r *MIBResolver) resolveParentOID(name string) string {
	if oid, ok := r.nameToOID[name]; ok {
		return oid
	}
	return ""
}

// syntaxToType converts SNMP SYNTAX to a simpler type name
func (r *MIBResolver) syntaxToType(syntax string) string {
	syntax = strings.ToLower(syntax)
	switch {
	case strings.HasPrefix(syntax, "counter64"):
		return "counter64"
	case strings.HasPrefix(syntax, "counter32"), strings.HasPrefix(syntax, "counter"):
		return "counter"
	case strings.HasPrefix(syntax, "gauge32"), strings.HasPrefix(syntax, "gauge"):
		return "gauge"
	case strings.HasPrefix(syntax, "integer"), strings.HasPrefix(syntax, "int"):
		return "integer"
	case strings.HasPrefix(syntax, "timeticks"):
		return "timeticks"
	case strings.HasPrefix(syntax, "displaystring"), strings.HasPrefix(syntax, "octet string"):
		return "string"
	case strings.HasPrefix(syntax, "ipaddress"):
		return "ipaddress"
	case strings.HasPrefix(syntax, "object identifier"):
		return "oid"
	default:
		return "unknown"
	}
}

// Resolve converts an OID to a human-readable MIBObject
func (r *MIBResolver) Resolve(oid string) (*MIBObject, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Exact match
	if obj, ok := r.oidToName[oid]; ok {
		return obj, true
	}

	// Find longest prefix match
	bestMatch := ""
	for knownOID := range r.oidToName {
		if strings.HasPrefix(oid, knownOID+".") && len(knownOID) > len(bestMatch) {
			bestMatch = knownOID
		}
	}

	if bestMatch != "" {
		obj := r.oidToName[bestMatch]
		suffix := strings.TrimPrefix(oid, bestMatch)
		return &MIBObject{
			OID:         oid,
			Name:        obj.Name + suffix,
			Module:      obj.Module,
			Type:        obj.Type,
			Description: obj.Description,
			EnumValues:  obj.EnumValues,
		}, true
	}

	return nil, false
}

// ResolveByName converts a name to an OID
func (r *MIBResolver) ResolveByName(name string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	oid, ok := r.nameToOID[name]
	return oid, ok
}

// ResolveEnumValue converts an integer value to its enum string
func (r *MIBResolver) ResolveEnumValue(oid string, value int) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if obj, ok := r.oidToName[oid]; ok && obj.EnumValues != nil {
		if enumStr, ok := obj.EnumValues[value]; ok {
			return enumStr, true
		}
	}
	return "", false
}

// GetObject returns a MIB object by name
func (r *MIBResolver) GetObject(name string) (*MIBObject, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	oid, ok := r.nameToOID[name]
	if !ok {
		return nil, false
	}
	obj, ok := r.oidToName[oid]
	return obj, ok
}

// ListModules returns the names of all loaded MIB modules
func (r *MIBResolver) ListModules() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	modules := make([]string, 0, len(r.modules))
	for name := range r.modules {
		modules = append(modules, name)
	}
	return modules
}

// GetModule returns a loaded MIB module by name
func (r *MIBResolver) GetModule(name string) (*MIBModule, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	module, ok := r.modules[name]
	return module, ok
}

// ParseOID parses an OID string into its numeric components
func ParseOID(oid string) ([]int, error) {
	parts := strings.Split(oid, ".")
	result := make([]int, len(parts))

	for i, part := range parts {
		if part == "" {
			continue
		}
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid OID component %q: %w", part, err)
		}
		result[i] = n
	}

	return result, nil
}

// FormatOID formats OID components back to a string
func FormatOID(components []int) string {
	parts := make([]string, len(components))
	for i, c := range components {
		parts[i] = strconv.Itoa(c)
	}
	return strings.Join(parts, ".")
}
