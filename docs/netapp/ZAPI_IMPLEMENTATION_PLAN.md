# ZAPI Implementation Plan for Telegen

## Overview
ZAPI (ONTAPI XML) support is required for pre-9.6 ONTAP clusters and certain objects only available via ZAPI. This document outlines the implementation plan for full ZAPI/ZapiPerf collector support.

## Current Status
- ✅ REST/RestPerf/KeyPerf collectors fully functional (9.6+)
- ⏳ ZAPI/ZapiPerf collectors: architecture documented, implementation pending

## Architecture Components

### 1. ZAPI Client (`internal/storage/netapp/client/zapi.go`)
**Purpose**: XML-RPC client for ONTAP ZAPI protocol

**Key Features**:
- XML request/response handling via `tree` package
- Handshake: `system-get-version` + `cluster-identity-get` (C-mode) or `system-get-info` (7-mode)
- Pagination: next-tag based batching for large result sets
- API version negotiation (default: 1.3)
- Vfiler tunneling support (7-mode)
- Auth retry on credential expiration

**API Surface**:
```go
type Client struct {
    client     *http.Client
    request    *http.Request
    buffer     *bytes.Buffer
    apiVersion string
    vfiler     string
    remote     conf.Remote
}

func New(config *storagedef.NetAppConfig, auth *auth.Credentials) (*Client, error)
func (c *Client) Init(retries int) error
func (c *Client) InvokeRequestString(request string) (*node.Node, error)
func (c *Client) InvokeRequest(request *node.Node) (*node.Node, error)
func (c *Client) InvokeBatchRequest(request *node.Node, tag string) (Response, error)
func (c *Client) InvokeZapiCall(request *node.Node) ([]*node.Node, error)
```

**Endpoints**:
- C-mode: `https://{addr}/servlets/netapp.servlets.admin.XMLrequest_filer`
- 7-mode: `https://{addr}:8443/servlets/netapp.servlets.admin.XMLrequest_filer` (KFS)

**Request Format**:
```xml
<netapp xmlns="http://www.netapp.com/filer/admin" version="1.3">
  <volume-get-iter>
    <max-records>500</max-records>
    <query>...</query>
    <desired-attributes>...</desired-attributes>
  </volume-get-iter>
</netapp>
```

### 2. XML Tree Package (`pkg/tree/`)
**Purpose**: XML DOM manipulation (imported from Harvest)

**Required Files**:
- `tree/tree.go`: XML encode/decode utilities
- `tree/node/node.go`: XML node structure with ZAPI-specific accessors

**Key Functions**:
```go
func LoadXML(data []byte) (*node.Node, error)
func DumpXML(n *node.Node) ([]byte, error)
func ImportXML(path string) (*node.Node, error)
```

### 3. ZAPI Collector (`internal/storage/netapp/zapi/collector.go`)
**Purpose**: Template-driven ZAPI collection (mirrors `rest/collector.go`)

**Template Structure** (ZAPI differs from REST):
```yaml
name: Volume
query: volume-get-iter  # ZAPI API name (not REST path)
object: volume

counters:
  - ^^volume-id-attributes.name              => volume
  - ^volume-id-attributes.owning-vserver-name => svm
  - volume-space-attributes.size-total       => size_total
  - volume-state-attributes.state            => state
```

**Key Differences from REST**:
- Nested XML paths (e.g., `volume-space-attributes.size-total`)
- `desired-attributes` XML block construction from counters
- Pagination via `next-tag` instead of REST `next` link
- Plugin integration identical to REST

### 4. ZapiPerf Collector (`internal/storage/netapp/zapiperf/collector.go`)
**Purpose**: Performance counter collection via ZAPI (pre-9.6 RestPerf alternative)

**ZAPI APIs**:
- `perf-object-counter-list-info`: get counter metadata
- `perf-object-instance-list-info-iter`: get instance list
- `perf-object-get-instances`: get counter values

**Counter Metadata** (`counter_schemas` equivalent):
```xml
<counters>
  <counter-info>
    <name>read_ops</name>
    <properties>delta,rate</properties>
    <base-counter>cpu_elapsed_time</base-counter>
  </counter-info>
</counters>
```

**Template Structure**:
```yaml
name: Volume
query: volume  # perf object name
object: volume

counters:
  - ^^instance_name => volume
  - read_ops        => read_ops
  - write_ops       => write_ops
  - total_ops       => total_ops
```

**Shared Cooking Path**: ZapiPerf feeds into `matrix.CookRates` (same as RestPerf).

### 5. Template Embedding
**Required Templates** (from Harvest `conf/zapi/` and `conf/zapiperf/`):
```
configs/netapp/zapi/
  cdot/9.8.0/*.yaml      # ZAPI templates for C-mode 9.8+
  default.yaml           # ZAPI default catalog
configs/netapp/zapiperf/
  cdot/9.8.0/*.yaml      # ZapiPerf templates for C-mode 9.8+
  default.yaml           # ZapiPerf default catalog
```

**Embed Directive**:
```go
//go:embed configs/netapp/zapi configs/netapp/zapiperf
var zapiTemplates embed.FS
```

### 6. REST/ZAPI Negotiation (`internal/storage/netapp/probe.go`)
**Purpose**: Auto-select REST or ZAPI based on ONTAP version

**Logic** (mirrors Harvest `upgradeCollector`):
```go
func (p *Probe) NegotiateProtocol() ([]string, error) {
    // Try REST first (9.6+)
    if p.capabilities.Version >= "9.6.0" && p.capabilities.RestAvailable {
        return []string{"rest", "restperf", "keyperf", "ems"}, nil
    }
    
    // Fall back to ZAPI for pre-9.6
    if p.capabilities.ZAPIAvailable {
        return []string{"zapi", "zapiperf", "ems"}, nil
    }
    
    return nil, errors.New("no supported protocol available")
}
```

**Version Thresholds**:
- REST: 9.6.0+
- ZAPI: 8.2.0 - 9.15.x (9.16+ removes ZAPI)
- 7-mode: ZAPI only

## Implementation Phases

### Phase 3.1: ZAPI Client (id: zapi-client) ⏳
**Deliverables**:
- `internal/storage/netapp/client/zapi.go` (XML-RPC client)
- `pkg/tree/tree.go` + `pkg/tree/node/node.go` (XML DOM)
- Unit tests for handshake, pagination, error handling

**Estimated Complexity**: 800-1000 lines

### Phase 3.2: ZAPI Collector (id: zapi-collector) ⏳
**Deliverables**:
- `internal/storage/netapp/zapi/collector.go` (template-driven ZAPI)
- `internal/storage/netapp/template/zapi_load.go` (XML path parsing)
- Integration with existing plugin dispatcher

**Estimated Complexity**: 600-800 lines

### Phase 3.3: ZapiPerf Collector (id: zapiperf) ⏳
**Deliverables**:
- `internal/storage/netapp/zapiperf/collector.go` (perf counter collection)
- Counter metadata caching
- Integration with `matrix.CookRates` (shared cooking path)

**Estimated Complexity**: 700-900 lines

### Phase 3.4: Template Embedding (id: zapi-templates) ⏳
**Deliverables**:
- Copy 60+ ZAPI templates from Harvest `conf/zapi/cdot/`
- Copy 30+ ZapiPerf templates from Harvest `conf/zapiperf/cdot/`
- Embed via `//go:embed` directive
- Update `template.LoadObjectTemplate` to handle ZAPI paths

**Estimated Complexity**: 90 templates, ~50KB

### Phase 3.5: Protocol Negotiation (id: negotiation) ⏳
**Deliverables**:
- `ProbeCapabilities` extended with ZAPI detection
- `NegotiateProtocol()` method
- Collector selection logic in `Start()`

**Estimated Complexity**: 200-300 lines

## Testing Strategy

### Unit Tests
- ZAPI client XML encoding/decoding
- Pagination logic (next-tag handling)
- Error response parsing
- Counter metadata parsing (ZapiPerf)

### Integration Tests
- Mock ZAPI server (XML responses)
- Template loading (ZAPI vs REST paths)
- Plugin dispatch (same plugins, different collectors)

### E2E Tests
- Pre-9.6 cluster (ZAPI only)
- 9.6-9.12 cluster (REST preferred, ZAPI fallback)
- 7-mode system (ZAPI only)

## Migration Notes

### For Users
- **No config changes required**: Protocol negotiation is automatic
- **Behavior**: Pre-9.6 clusters auto-select ZAPI collectors
- **Metrics**: Identical metric names between REST and ZAPI collectors

### For Operators
- **Air-gapped**: ZAPI templates embedded in binary (same as REST)
- **Debugging**: Set `log_set: [Zapi]` to log XML requests/responses

## References

### Harvest Implementation
- Client: `pkg/api/ontapi/zapi/client.go` (606 lines)
- Collector: `cmd/collectors/zapi/collector/zapi.go` (568 lines)
- ZapiPerf: `cmd/collectors/zapiperf/zapiperf.go` (851 lines)

### ONTAP Documentation
- ZAPI Developer Guide: https://library.netapp.com/ecmdocs/ECMP1511536/html/
- ONTAPI API Reference: https://library.netapp.com/ecm/ecm_download_file/ECMLP2858435

## Status Summary
- **Phase 3.1-3.5**: Architecture documented, ready for implementation
- **Estimated Total Effort**: 2500-3000 lines across 5 phases
- **Priority**: Medium (REST collectors cover 90% of deployments)
- **Blocker**: None (REST/RestPerf/KeyPerf fully functional)

---
*Document created: 2026-08-13*
*Author: Telegen NetApp Plugin Team*
*Status: Architecture Complete, Implementation Pending*
