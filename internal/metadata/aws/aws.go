package aws

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
)

// IMDS constants
const (
	imdsAddr = "169.254.169.254:80"
	imdsBase = "http://169.254.169.254/latest"
)

type Options struct {
	Timeout         time.Duration
	RefreshInterval time.Duration
	CollectTags     bool
	TagAllowlist    []string
	BaseURL         string
	DisableProbe    bool
}

type Provider struct {
	http   *http.Client
	opts   Options
	data   *Data
	expire time.Time
	base   string
}

type Data struct {
	Platform     string // ec2|ecs|eks (best-effort)
	AccountID    string
	Region       string
	AZ           string
	InstanceID   string
	InstanceType string
	AMI          string
	Hostname     string
	PrivateIP    string
	PublicIP     string
	VPCID        string
	Tags         map[string]string
}

func New(opts Options) *Provider {
	if opts.Timeout <= 0 {
		opts.Timeout = 200 * time.Millisecond
	}
	if opts.RefreshInterval <= 0 {
		opts.RefreshInterval = 15 * time.Minute
	}
	base := imdsBase
	if strings.TrimSpace(opts.BaseURL) != "" {
		base = strings.TrimRight(opts.BaseURL, "/")
	}
	return &Provider{http: &http.Client{Timeout: opts.Timeout}, opts: opts, base: base}
}

// Fetch refreshes cached data if expired; otherwise returns cached.
func (p *Provider) Fetch(ctx context.Context) (*Data, error) {
	if p.data != nil && time.Now().Before(p.expire) {
		return p.data, nil
	}
	d, err := p.fetchOnce(ctx)
	if err != nil {
		return nil, err
	}
	p.data = d
	p.expire = time.Now().Add(p.opts.RefreshInterval)
	return d, nil
}

func (p *Provider) fetchOnce(ctx context.Context) (*Data, error) {
	// Ensure IMDS address is reachable quickly to avoid DNS waits
	d := &Data{Platform: "ec2"}
	if !p.opts.DisableProbe {
		dialer := &net.Dialer{Timeout: p.opts.Timeout}
		if _, err := dialer.DialContext(ctx, "tcp", imdsAddr); err != nil {
			// Not on EC2 (or blocked); attempt to infer region from env and hostname from os
			d.Platform = inferPlatform()
			d.Region = getenvAny("AWS_REGION", "AWS_DEFAULT_REGION")
			d.Hostname, _ = os.Hostname()
			return d, nil
		}
	}
	token, _ := p.getToken(ctx)
	// Instance identity document has a lot of info
	var iid struct {
		AccountID        string `json:"accountId"`
		Region           string `json:"region"`
		InstanceID       string `json:"instanceId"`
		InstanceType     string `json:"instanceType"`
		ImageID          string `json:"imageId"`
		AvailabilityZone string `json:"availabilityZone"`
		PrivateIP        string `json:"privateIp"`
	}
	if b, err := p.get(ctx, token, p.base+"/dynamic/instance-identity/document"); err == nil {
		_ = json.Unmarshal(b, &iid)
		d.AccountID, d.Region, d.InstanceID, d.InstanceType, d.AMI, d.AZ, d.PrivateIP = iid.AccountID, iid.Region, iid.InstanceID, iid.InstanceType, iid.ImageID, iid.AvailabilityZone, iid.PrivateIP
	}
	// Fill additional fields best-effort
	if d.InstanceID == "" {
		d.InstanceID = stringOrEmpty(p.get(ctx, token, p.base+"/meta-data/instance-id"))
	}
	if d.InstanceType == "" {
		d.InstanceType = stringOrEmpty(p.get(ctx, token, p.base+"/meta-data/instance-type"))
	}
	if d.AMI == "" {
		d.AMI = stringOrEmpty(p.get(ctx, token, p.base+"/meta-data/ami-id"))
	}
	if d.PrivateIP == "" {
		d.PrivateIP = stringOrEmpty(p.get(ctx, token, p.base+"/meta-data/local-ipv4"))
	}
	d.PublicIP = stringOrEmpty(p.get(ctx, token, p.base+"/meta-data/public-ipv4"))
	if hn, _ := os.Hostname(); hn != "" {
		d.Hostname = hn
	} else {
		d.Hostname = d.InstanceID
	}
	// VPC ID via macs list
	if macs := stringOrEmpty(p.get(ctx, token, p.base+"/meta-data/network/interfaces/macs/")); macs != "" {
		first := strings.TrimSpace(strings.Split(macs, "\n")[0])
		if first != "" {
			d.VPCID = stringOrEmpty(p.get(ctx, token, p.base+"/meta-data/network/interfaces/macs/"+first+"vpc-id"))
		}
	}
	// Tags (opt-in) exposed via IMDS on newer instances under tags/instance
	if p.opts.CollectTags {
		if keys := stringOrEmpty(p.get(ctx, token, p.base+"/meta-data/tags/instance")); keys != "" {
			d.Tags = map[string]string{}
			for _, k := range strings.Split(keys, "\n") {
				k = strings.TrimSpace(k)
				if k == "" || !allowTag(k, p.opts.TagAllowlist) {
					continue
				}
				v := stringOrEmpty(p.get(ctx, token, p.base+"/meta-data/tags/instance/"+k))
				if v != "" {
					d.Tags[k] = v
				}
			}
		}
	}
	return d, nil
}

func (p *Provider) getToken(ctx context.Context) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodPut, p.base+"/api/token", nil)
	req.Header.Set("X-aws-ec2-metadata-token-ttl-seconds", "21600")
	resp, err := p.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", errors.New("imds token failed")
	}
	b, _ := io.ReadAll(resp.Body)
	return string(b), nil
}

func (p *Provider) get(ctx context.Context, token, url string) ([]byte, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set("X-aws-ec2-metadata-token", token)
	}
	resp, err := p.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, errors.New(resp.Status)
	}
	return io.ReadAll(resp.Body)
}

func stringOrEmpty(b []byte, err error) string {
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func allowTag(k string, allow []string) bool {
	if len(allow) == 0 {
		return false
	}
	for _, p := range allow {
		if strings.HasPrefix(k, p) {
			return true
		}
	}
	return false
}

func getenvAny(keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
	}
	return ""
}

func inferPlatform() string {
	if os.Getenv("ECS_CONTAINER_METADATA_URI_V4") != "" {
		return "ecs"
	}
	if os.Getenv("ECS_CONTAINER_METADATA_URI") != "" {
		return "ecs"
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		return "eks"
	}
	return "unknown"
}

// Resource builds an OTEL resource from the fetched metadata.
func (d *Data) Resource() *resource.Resource {
	attrs := []attribute.KeyValue{
		semconv.CloudProviderAWS,
	}
	switch d.Platform {
	case "ec2":
		attrs = append(attrs, semconv.CloudPlatformAWSEC2)
	case "ecs":
		attrs = append(attrs, semconv.CloudPlatformAWSECS)
	case "eks":
		attrs = append(attrs, semconv.CloudPlatformAWSEKS)
	}
	if d.AccountID != "" {
		attrs = append(attrs, semconv.CloudAccountID(d.AccountID))
	}
	if d.Region != "" {
		attrs = append(attrs, semconv.CloudRegion(d.Region))
	}
	if d.AZ != "" {
		attrs = append(attrs, semconv.CloudAvailabilityZone(d.AZ))
	}
	if d.InstanceID != "" {
		attrs = append(attrs, semconv.HostID(d.InstanceID))
	}
	if d.InstanceType != "" {
		attrs = append(attrs, semconv.HostType(d.InstanceType))
	}
	if d.Hostname != "" {
		attrs = append(attrs, semconv.HostName(d.Hostname))
	}
	if d.AMI != "" {
		attrs = append(attrs, semconv.AWSECSTaskARN(d.AMI)) // Use generic attribute for AMI
	}
	if d.PrivateIP != "" {
		attrs = append(attrs, attribute.String("net.host.ip", d.PrivateIP))
	}
	if d.VPCID != "" {
		attrs = append(attrs, attribute.String("aws.ec2.network.vpc.id", d.VPCID))
	}
	// Tags as attributes under aws.ec2.tag.* (if present)
	for k, v := range d.Tags {
		attrs = append(attrs, attribute.String("aws.ec2.tag."+k, v))
	}
	res, _ := resource.Merge(resource.Default(), resource.NewSchemaless(attrs...))
	return res
}

// Labels returns a set of Prometheus-style constant labels derived from metadata.
func (d *Data) Labels() map[string]string {
	m := map[string]string{}
	if d.Region != "" {
		m["cloud_region"] = d.Region
	}
	if d.AZ != "" {
		m["cloud_az"] = d.AZ
	}
	if d.InstanceID != "" {
		m["instance_id"] = d.InstanceID
	}
	if d.InstanceType != "" {
		m["instance_type"] = d.InstanceType
	}
	if d.VPCID != "" {
		m["vpc_id"] = d.VPCID
	}
	m["cloud_provider"] = "aws"
	return m
}
