// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package snmp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
)

// RemoteWriteClient sends metrics to Prometheus-compatible remote write endpoints
type RemoteWriteClient struct {
	config    RemoteWriteConfig
	log       *slog.Logger
	endpoints []*RemoteWriteEndpoint

	queue   chan []Metric
	stopCh  chan struct{}
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex
}

// RemoteWriteEndpoint represents a single remote write destination
type RemoteWriteEndpoint struct {
	config RemoteWriteEndpointConfig
	client *http.Client
	log    *slog.Logger

	// Retry state
	retryCount int
	lastError  error
}

// NewRemoteWriteClient creates a new remote write client
func NewRemoteWriteClient(cfg RemoteWriteConfig, log *slog.Logger) (*RemoteWriteClient, error) {
	if log == nil {
		log = slog.Default()
	}
	log = log.With("component", "remote-write")

	c := &RemoteWriteClient{
		config:    cfg,
		log:       log,
		endpoints: make([]*RemoteWriteEndpoint, 0, len(cfg.Endpoints)),
		queue:     make(chan []Metric, 10000),
		stopCh:    make(chan struct{}),
	}

	// Create endpoints
	for _, epCfg := range cfg.Endpoints {
		timeout := epCfg.Timeout
		if timeout == 0 {
			timeout = 30 * time.Second
		}

		ep := &RemoteWriteEndpoint{
			config: epCfg,
			client: &http.Client{
				Timeout: timeout,
			},
			log: log.With("endpoint", epCfg.URL),
		}
		c.endpoints = append(c.endpoints, ep)
	}

	return c, nil
}

// Start starts the remote write client
func (c *RemoteWriteClient) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	c.log.Info("starting remote write client", "endpoints", len(c.endpoints))

	// Start worker goroutine
	c.wg.Add(1)
	go c.worker(ctx)

	c.running = true
	return nil
}

// Stop stops the remote write client
func (c *RemoteWriteClient) Stop(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return nil
	}

	c.log.Info("stopping remote write client")

	close(c.stopCh)
	c.wg.Wait()

	c.running = false
	return nil
}

// Send queues metrics for sending
func (c *RemoteWriteClient) Send(ctx context.Context, metrics []Metric) error {
	select {
	case c.queue <- metrics:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	default:
		return fmt.Errorf("remote write queue full")
	}
}

// worker processes the metric queue
func (c *RemoteWriteClient) worker(ctx context.Context) {
	defer c.wg.Done()

	batch := make([]Metric, 0, 1000)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			if len(batch) > 0 {
				c.flush(context.Background(), batch)
			}
			return
		case <-c.stopCh:
			if len(batch) > 0 {
				c.flush(context.Background(), batch)
			}
			return
		case metrics := <-c.queue:
			batch = append(batch, metrics...)
			if len(batch) >= 1000 {
				c.flush(ctx, batch)
				batch = batch[:0]
			}
		case <-ticker.C:
			if len(batch) > 0 {
				c.flush(ctx, batch)
				batch = batch[:0]
			}
		}
	}
}

// flush sends a batch of metrics to all endpoints
func (c *RemoteWriteClient) flush(ctx context.Context, metrics []Metric) {
	if len(metrics) == 0 {
		return
	}

	// Convert to Prometheus remote write format
	req := c.buildWriteRequest(metrics)

	// Send to all endpoints concurrently
	var wg sync.WaitGroup
	for _, ep := range c.endpoints {
		wg.Add(1)
		go func(endpoint *RemoteWriteEndpoint) {
			defer wg.Done()
			if err := endpoint.send(ctx, req); err != nil {
				endpoint.log.Error("failed to send metrics", "error", err)
			}
		}(ep)
	}
	wg.Wait()
}

// buildWriteRequest converts metrics to a Prometheus WriteRequest
func (c *RemoteWriteClient) buildWriteRequest(metrics []Metric) *prompb.WriteRequest {
	timeseries := make([]prompb.TimeSeries, 0, len(metrics))

	for _, m := range metrics {
		labels := make([]prompb.Label, 0, len(m.Labels)+1)

		// Add __name__ label
		labels = append(labels, prompb.Label{
			Name:  "__name__",
			Value: m.Name,
		})

		// Add other labels
		for k, v := range m.Labels {
			labels = append(labels, prompb.Label{
				Name:  k,
				Value: v,
			})
		}

		ts := prompb.TimeSeries{
			Labels: labels,
			Samples: []prompb.Sample{
				{
					Value:     m.Value,
					Timestamp: m.Timestamp.UnixMilli(),
				},
			},
		}
		timeseries = append(timeseries, ts)
	}

	return &prompb.WriteRequest{
		Timeseries: timeseries,
	}
}

// send sends a write request to the endpoint
func (ep *RemoteWriteEndpoint) send(ctx context.Context, req *prompb.WriteRequest) error {
	// Marshal the request
	data, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal write request: %w", err)
	}

	// Compress with snappy
	compressed := snappy.Encode(nil, data)

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.config.URL, bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-protobuf")
	httpReq.Header.Set("Content-Encoding", "snappy")
	httpReq.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")

	// Add custom headers
	for k, v := range ep.config.Headers {
		httpReq.Header.Set(k, v)
	}

	// Add basic auth if configured
	if ep.config.BasicAuth != nil {
		httpReq.SetBasicAuth(ep.config.BasicAuth.Username, ep.config.BasicAuth.Password)
	}

	// Send request
	resp, err := ep.client.Do(httpReq)
	if err != nil {
		ep.retryCount++
		ep.lastError = err
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	// Check response
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
		err := fmt.Errorf("remote write failed with status %d: %s", resp.StatusCode, string(body))
		ep.retryCount++
		ep.lastError = err
		return err
	}

	// Reset retry count on success
	ep.retryCount = 0
	ep.lastError = nil

	return nil
}

// Status returns the status of an endpoint
func (ep *RemoteWriteEndpoint) Status() (int, error) {
	return ep.retryCount, ep.lastError
}
