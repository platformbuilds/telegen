package config

import (
    "os"
    "time"
    "gopkg.in/yaml.v3"
)

type TLS struct {
    Enable   bool   `yaml:"enable"`
    CAFile   string `yaml:"ca_file"`
    CertFile string `yaml:"cert_file"`
    KeyFile  string `yaml:"key_file"`
    InsecureSkipVerify bool `yaml:"insecure_skip_verify"`
}

type Config struct {
    Agent struct{ ServiceName string `yaml:"service_name"` } `yaml:"agent"`
    SelfTelemetry struct {
        Listen string `yaml:"listen"`
        NS     string `yaml:"prometheus_namespace"`
    } `yaml:"selfTelemetry"`
    Queues struct {
        Metrics Q `yaml:"metrics"`
        Traces  Q `yaml:"traces"`
        Logs    Q `yaml:"logs"`
    } `yaml:"queues"`
    Backoff struct {
        Initial    string  `yaml:"initial"`
        Max        string  `yaml:"max"`
        Multiplier float64 `yaml:"multiplier"`
        Jitter     float64 `yaml:"jitter"`
    } `yaml:"backoff"`
    Exports struct {
        RemoteWrite RemoteWrite `yaml:"remoteWrite"`
        OTLP        OTLP        `yaml:"otlp"`
    } `yaml:"exports"`
    Pipelines struct {
        Metrics struct{ AlsoExposeProm bool `yaml:"also_expose_prometheus"` } `yaml:"metrics"`
        Traces  struct{ Enabled bool } `yaml:"traces"`
        Logs    struct{ Enabled bool; Filelog struct{
            Include []string `yaml:"include"`
            PositionFile string `yaml:"position_file"`
        } `yaml:"filelog"` } `yaml:"logs"`
    } `yaml:"pipelines"`
}

type Q struct {
    MemLimit string `yaml:"mem_limit"`
    MaxAgeStr string `yaml:"max_age"`
}
func (q Q) MaxAge() time.Duration { d,_ := time.ParseDuration(q.MaxAgeStr); return d }

type RemoteWrite struct {
    Mode string `yaml:"mode"`
    TLS  TLS    `yaml:"tls"`
    Endpoints []RWEndpoint `yaml:"endpoints"`
}
type RWEndpoint struct {
    URL string `yaml:"url"`
    Timeout string `yaml:"timeout"`
    Headers map[string]string `yaml:"headers"`
    Tenant string `yaml:"tenant"`
    Compression string `yaml:"compression"`
}

type OTLP struct {
    SendMode string `yaml:"send_mode"`
    TLS TLS `yaml:"tls"`
    GRPC struct{
        Enabled bool `yaml:"enabled"`
        Endpoint string `yaml:"endpoint"`
        Headers map[string]string `yaml:"headers"`
        Insecure bool `yaml:"insecure"`
        Gzip bool `yaml:"gzip"`
        Timeout string `yaml:"timeout"`
    } `yaml:"grpc"`
    HTTP struct{
        Enabled bool `yaml:"enabled"`
        Endpoint string `yaml:"endpoint"`
        TracesPath string `yaml:"traces_path"`
        LogsPath string `yaml:"logs_path"`
        Headers map[string]string `yaml:"headers"`
        Gzip bool `yaml:"gzip"`
        Timeout string `yaml:"timeout"`
    } `yaml:"http"`
}

func Load(path string) (*Config, error) {
    b, err := os.ReadFile(path); if err != nil { return nil, err }
    var c Config
    if err := yaml.Unmarshal(b, &c); err != nil { return nil, err }
    if c.SelfTelemetry.Listen == "" { c.SelfTelemetry.Listen = ":19090" }
    return &c, nil
}
