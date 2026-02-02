package unified

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// PublicCloudDetector performs parallel detection of public cloud environments.
type PublicCloudDetector struct {
	client  *http.Client
	timeout time.Duration
}

// PublicCloudEndpoint defines a cloud provider's metadata endpoint.
type PublicCloudEndpoint struct {
	Provider string
	URL      string
	Headers  map[string]string
	Timeout  time.Duration
}

// publicCloudEndpoints lists all public cloud metadata endpoints for detection.
var publicCloudEndpoints = []PublicCloudEndpoint{
	{
		Provider: "aws",
		URL:      "http://169.254.169.254/latest/api/token",
		Headers:  map[string]string{"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
		Timeout:  1 * time.Second,
	},
	{
		Provider: "gcp",
		URL:      "http://metadata.google.internal/computeMetadata/v1/",
		Headers:  map[string]string{"Metadata-Flavor": "Google"},
		Timeout:  1 * time.Second,
	},
	{
		Provider: "azure",
		URL:      "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
		Headers:  map[string]string{"Metadata": "true"},
		Timeout:  1 * time.Second,
	},
	{
		Provider: "alibaba",
		URL:      "http://100.100.100.200/latest/meta-data/",
		Headers:  nil,
		Timeout:  1 * time.Second,
	},
	{
		Provider: "oracle",
		URL:      "http://169.254.169.254/opc/v2/instance/",
		Headers:  map[string]string{"Authorization": "Bearer Oracle"},
		Timeout:  1 * time.Second,
	},
	{
		Provider: "digitalocean",
		URL:      "http://169.254.169.254/metadata/v1/",
		Headers:  nil,
		Timeout:  1 * time.Second,
	},
}

// NewPublicCloudDetector creates a new public cloud detector.
func NewPublicCloudDetector() *PublicCloudDetector {
	return &PublicCloudDetector{
		client: &http.Client{
			Timeout: 2 * time.Second,
			Transport: &http.Transport{
				DisableKeepAlives: true,
			},
		},
		timeout: 2 * time.Second,
	}
}

// DetectionResult holds the result of a cloud detection attempt.
type DetectionResult struct {
	Provider string
	Detected bool
	Error    error
}

// DetectAll tries all public cloud endpoints in parallel.
// Returns the first successfully detected provider.
func (d *PublicCloudDetector) DetectAll(ctx context.Context) (string, error) {
	type result struct {
		provider string
		success  bool
	}

	results := make(chan result, len(publicCloudEndpoints))
	var wg sync.WaitGroup

	for _, endpoint := range publicCloudEndpoints {
		wg.Add(1)
		go func(ep PublicCloudEndpoint) {
			defer wg.Done()

			detected := d.checkEndpoint(ctx, ep)
			results <- result{
				provider: ep.Provider,
				success:  detected,
			}
		}(endpoint)
	}

	// Close results when all checks complete
	go func() {
		wg.Wait()
		close(results)
	}()

	// Return first successful detection
	for r := range results {
		if r.success {
			return r.provider, nil
		}
	}

	return "", nil
}

// DetectProvider checks a specific provider.
func (d *PublicCloudDetector) DetectProvider(ctx context.Context, provider string) bool {
	for _, ep := range publicCloudEndpoints {
		if ep.Provider == provider {
			return d.checkEndpoint(ctx, ep)
		}
	}
	return false
}

// checkEndpoint tests if a metadata endpoint is accessible.
func (d *PublicCloudDetector) checkEndpoint(ctx context.Context, ep PublicCloudEndpoint) bool {
	timeout := ep.Timeout
	if timeout == 0 {
		timeout = d.timeout
	}

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	method := http.MethodGet
	// AWS IMDSv2 requires PUT for token
	if ep.Provider == "aws" && strings.Contains(ep.URL, "/api/token") {
		method = http.MethodPut
	}

	req, err := http.NewRequestWithContext(ctx, method, ep.URL, nil)
	if err != nil {
		return false
	}

	for k, v := range ep.Headers {
		req.Header.Set(k, v)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain body to allow connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)

	// Consider 200-299 as success
	return resp.StatusCode >= 200 && resp.StatusCode < 300
}

// GetSupportedProviders returns the list of supported public cloud providers.
func (d *PublicCloudDetector) GetSupportedProviders() []string {
	providers := make([]string, len(publicCloudEndpoints))
	for i, ep := range publicCloudEndpoints {
		providers[i] = ep.Provider
	}
	return providers
}
