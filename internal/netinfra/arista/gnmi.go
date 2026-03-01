// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package arista

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/openconfig/gnmi/proto/gnmi"
	"github.com/mirastacklabs-ai/telegen/internal/netinfra/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// GNMIClient provides gNMI streaming telemetry for CloudVision
type GNMIClient struct {
	config  Config
	log     *slog.Logger
	conn    *grpc.ClientConn
	client  gnmi.GNMIClient
	metrics chan *types.NetworkMetric

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.RWMutex
	running bool
}

// NewGNMIClient creates a new gNMI client
func NewGNMIClient(cfg Config, log *slog.Logger) (*GNMIClient, error) {
	if !cfg.GNMI.Enabled {
		return nil, fmt.Errorf("gNMI is not enabled")
	}

	if cfg.GNMI.Address == "" {
		// Default to CVP address with gNMI port
		cfg.GNMI.Address = cfg.CVPURL + ":6030"
	}

	return &GNMIClient{
		config:  cfg,
		log:     log.With("component", "gnmi"),
		metrics: make(chan *types.NetworkMetric, 10000),
	}, nil
}

// Start starts the gNMI streaming client
func (c *GNMIClient) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.running {
		return nil
	}

	c.ctx, c.cancel = context.WithCancel(ctx)

	// Create gRPC connection
	var opts []grpc.DialOption
	if c.config.VerifySSL {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{})))
	} else {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	}

	conn, err := grpc.DialContext(c.ctx, c.config.GNMI.Address, opts...) //nolint:staticcheck // SA1019: grpc.DialContext still supported in 1.x
	if err != nil {
		return fmt.Errorf("failed to connect to gNMI server: %w", err)
	}
	c.conn = conn
	c.client = gnmi.NewGNMIClient(conn)

	// Start subscription workers
	for _, path := range c.config.GNMI.SubscribePaths {
		c.wg.Add(1)
		go c.subscribe(path)
	}

	c.running = true
	c.log.Info("gNMI client started", "address", c.config.GNMI.Address)
	return nil
}

// Stop stops the gNMI client
func (c *GNMIClient) Stop() {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.running {
		return
	}

	c.cancel()
	c.wg.Wait()

	if c.conn != nil {
		_ = c.conn.Close()
	}

	close(c.metrics)
	c.running = false
	c.log.Info("gNMI client stopped")
}

// Metrics returns the metrics channel
func (c *GNMIClient) Metrics() <-chan *types.NetworkMetric {
	return c.metrics
}

// subscribe subscribes to a gNMI path
func (c *GNMIClient) subscribe(pathStr string) {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		err := c.subscribeOnce(pathStr)
		if err != nil {
			c.log.Warn("gNMI subscription error, retrying", "path", pathStr, "error", err)
			select {
			case <-c.ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// subscribeOnce performs a single subscription attempt
func (c *GNMIClient) subscribeOnce(pathStr string) error {
	// Parse the path
	path, err := parsePath(pathStr)
	if err != nil {
		return fmt.Errorf("failed to parse path: %w", err)
	}

	// Create subscription request
	req := &gnmi.SubscribeRequest{
		Request: &gnmi.SubscribeRequest_Subscribe{
			Subscribe: &gnmi.SubscriptionList{
				Mode:     gnmi.SubscriptionList_STREAM,
				Encoding: gnmi.Encoding_JSON_IETF,
				Subscription: []*gnmi.Subscription{
					{
						Path:           path,
						Mode:           gnmi.SubscriptionMode_SAMPLE,
						SampleInterval: uint64(c.config.GNMI.SampleInterval.Nanoseconds()),
					},
				},
			},
		},
	}

	// Add authentication metadata
	ctx := c.ctx
	if c.config.Token != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+c.config.Token)
	}

	// Create stream
	stream, err := c.client.Subscribe(ctx)
	if err != nil {
		return fmt.Errorf("failed to subscribe: %w", err)
	}

	// Send subscription request
	if err := stream.Send(req); err != nil {
		return fmt.Errorf("failed to send subscribe request: %w", err)
	}

	// Receive updates
	for {
		resp, err := stream.Recv()
		if err != nil {
			return fmt.Errorf("stream receive error: %w", err)
		}

		switch r := resp.Response.(type) {
		case *gnmi.SubscribeResponse_Update:
			c.handleUpdate(r.Update)
		case *gnmi.SubscribeResponse_SyncResponse:
			c.log.Debug("gNMI sync complete", "path", pathStr)
		}
	}
}

// handleUpdate processes a gNMI notification
func (c *GNMIClient) handleUpdate(notification *gnmi.Notification) {
	timestamp := time.Unix(0, notification.Timestamp)
	prefix := pathToString(notification.Prefix)

	for _, update := range notification.Update {
		path := prefix + pathToString(update.Path)
		value := extractValue(update.Val)

		if value != nil {
			labels := c.baseLabels()
			labels["path"] = path

			metric := &types.NetworkMetric{
				Name:      "arista_gnmi_value",
				Value:     *value,
				Labels:    labels,
				Timestamp: timestamp,
				Type:      types.MetricTypeGauge,
			}

			select {
			case c.metrics <- metric:
			default:
				c.log.Warn("gNMI metrics channel full, dropping metric")
			}
		}
	}
}

// baseLabels returns base labels for gNMI metrics
func (c *GNMIClient) baseLabels() map[string]string {
	return map[string]string{
		"cvp":    c.config.Name,
		"vendor": "arista",
		"source": "gnmi",
	}
}

// parsePath parses a path string into a gNMI Path
func parsePath(pathStr string) (*gnmi.Path, error) {
	if pathStr == "" {
		return &gnmi.Path{}, nil
	}

	// Simple path parsing - split by /
	var elems []*gnmi.PathElem
	for _, elem := range splitPath(pathStr) {
		if elem == "" {
			continue
		}
		elems = append(elems, &gnmi.PathElem{Name: elem})
	}

	return &gnmi.Path{Elem: elems}, nil
}

// splitPath splits a path string into elements
func splitPath(path string) []string {
	var result []string
	var current string
	inBracket := false

	for _, r := range path {
		switch r {
		case '/':
			if !inBracket {
				if current != "" {
					result = append(result, current)
				}
				current = ""
				continue
			}
		case '[':
			inBracket = true
		case ']':
			inBracket = false
		}
		current += string(r)
	}

	if current != "" {
		result = append(result, current)
	}

	return result
}

// pathToString converts a gNMI Path to string
func pathToString(path *gnmi.Path) string {
	if path == nil {
		return ""
	}

	result := ""
	for _, elem := range path.Elem {
		result += "/" + elem.Name
		for k, v := range elem.Key {
			result += fmt.Sprintf("[%s=%s]", k, v)
		}
	}
	return result
}

// extractValue extracts a float64 value from a gNMI TypedValue
func extractValue(val *gnmi.TypedValue) *float64 {
	if val == nil {
		return nil
	}

	var result float64

	switch v := val.Value.(type) {
	case *gnmi.TypedValue_IntVal:
		result = float64(v.IntVal)
	case *gnmi.TypedValue_UintVal:
		result = float64(v.UintVal)
	case *gnmi.TypedValue_FloatVal:
		result = float64(v.FloatVal) //nolint:staticcheck // SA1019: FloatVal still used by some gNMI servers
	case *gnmi.TypedValue_DoubleVal:
		result = v.DoubleVal
	default:
		return nil
	}

	return &result
}
