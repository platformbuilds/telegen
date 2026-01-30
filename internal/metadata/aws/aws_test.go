package aws

import (
    "context"
    "encoding/json"
    "net/http"
    "net/http/httptest"
    "strings"
    "testing"
    "time"
)

func imdsServer() *httptest.Server {
    mux := http.NewServeMux()
    mux.HandleFunc("/latest/api/token", func(w http.ResponseWriter, r *http.Request){
        if r.Method != http.MethodPut { w.WriteHeader(405); return }
        w.WriteHeader(200); w.Write([]byte("tkn"))
    })
    mux.HandleFunc("/latest/dynamic/instance-identity/document", func(w http.ResponseWriter, r *http.Request){
        w.Header().Set("Content-Type","application/json")
        json.NewEncoder(w).Encode(map[string]any{
            "accountId":"123456789012",
            "region":"us-west-2",
            "instanceId":"i-abc123",
            "instanceType":"t3.small",
            "imageId":"ami-123",
            "availabilityZone":"us-west-2a",
            "privateIp":"10.0.0.5",
        })
    })
    mux.HandleFunc("/latest/meta-data/public-ipv4", func(w http.ResponseWriter, r *http.Request){ w.Write([]byte("54.1.2.3")) })
    mux.HandleFunc("/latest/meta-data/network/interfaces/macs/", func(w http.ResponseWriter, r *http.Request){ w.Write([]byte("aa:bb:cc:dd:ee:ff/\n")) })
    mux.HandleFunc("/latest/meta-data/network/interfaces/macs/aa:bb:cc:dd:ee:ff/vpc-id", func(w http.ResponseWriter, r *http.Request){ w.Write([]byte("vpc-123")) })
    mux.HandleFunc("/latest/meta-data/tags/instance", func(w http.ResponseWriter, r *http.Request){ w.Write([]byte("env\nignored\n")) })
    mux.HandleFunc("/latest/meta-data/tags/instance/env", func(w http.ResponseWriter, r *http.Request){ w.Write([]byte("prod")) })
    return httptest.NewServer(mux)
}

func TestProviderFetchAndResource(t *testing.T) {
    srv := imdsServer(); defer srv.Close()
    base := strings.TrimRight(srv.URL, "/") + "/latest"
    p := New(Options{ Timeout: 100 * time.Millisecond, RefreshInterval: time.Minute, CollectTags: true, TagAllowlist: []string{"env"}, BaseURL: base, DisableProbe: true })
    ctx := context.Background()
    d, err := p.Fetch(ctx)
    if err != nil { t.Fatalf("fetch: %v", err) }
    if d.AccountID != "123456789012" || d.Region != "us-west-2" || d.InstanceID != "i-abc123" || d.AZ != "us-west-2a" {
        t.Fatalf("unexpected data: %+v", d)
    }
    if d.VPCID != "vpc-123" || d.Tags["env"] != "prod" { t.Fatalf("missing vpc/tags: %+v", d) }
    res := d.Resource()
    got := map[string]bool{}
    for _, a := range res.Attributes() { got[string(a.Key)] = true }
    // Spot-check a few keys exist
    for _, k := range []string{"cloud.provider", "cloud.region", "cloud.availability_zone", "host.id"} {
        if !got[k] { t.Fatalf("resource missing %s", k) }
    }
}

