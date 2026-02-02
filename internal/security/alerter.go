// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// Alerter sends security alerts to configured destinations
// Task: SEC-017
type Alerter struct {
	config       AlertingConfig
	logger       *slog.Logger
	rateLimiter  *rate.Limiter
	httpClient   *http.Client
	destinations []alertDestination
	mu           sync.RWMutex //nolint:unused // reserved for thread-safe destination management
}

type alertDestination interface {
	Send(ctx context.Context, alert *Alert) error
	Type() string
}

// NewAlerter creates a new alerter
func NewAlerter(cfg AlertingConfig, logger *slog.Logger) *Alerter {
	if logger == nil {
		logger = slog.Default()
	}

	a := &Alerter{
		config: cfg,
		logger: logger,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		destinations: make([]alertDestination, 0),
	}

	// Initialize rate limiter if enabled
	if cfg.RateLimiting.Enabled {
		a.rateLimiter = rate.NewLimiter(
			rate.Limit(float64(cfg.RateLimiting.MaxAlertsPerMin)/60.0),
			cfg.RateLimiting.BurstSize,
		)
	}

	// Initialize destinations
	for _, dest := range cfg.Destinations {
		switch dest.Type {
		case "log":
			a.destinations = append(a.destinations, &logDestination{logger: logger})
		case "webhook":
			a.destinations = append(a.destinations, &webhookDestination{
				url:    dest.URL,
				client: a.httpClient,
				logger: logger,
			})
		case "slack":
			a.destinations = append(a.destinations, &slackDestination{
				webhookURL: dest.URL,
				client:     a.httpClient,
				logger:     logger,
			})
		default:
			logger.Warn("unknown alert destination type", "type", dest.Type)
		}
	}

	// Always add log destination as fallback
	if len(a.destinations) == 0 {
		a.destinations = append(a.destinations, &logDestination{logger: logger})
	}

	return a
}

// Send sends an alert to all configured destinations
func (a *Alerter) Send(ctx context.Context, alert *Alert) error {
	// Check rate limiting
	if a.rateLimiter != nil && !a.rateLimiter.Allow() {
		a.logger.Debug("alert rate limited", "alert_id", alert.ID)
		return nil
	}

	// Check severity threshold
	if alert.Severity.Number() < a.config.MinSeverity.Number() {
		return nil
	}

	var lastErr error
	for _, dest := range a.destinations {
		if err := dest.Send(ctx, alert); err != nil {
			a.logger.Error("failed to send alert",
				"destination", dest.Type(),
				"alert_id", alert.ID,
				"error", err)
			lastErr = err
		}
	}

	return lastErr
}

// logDestination logs alerts using slog
type logDestination struct {
	logger *slog.Logger
}

func (d *logDestination) Type() string { return "log" }

func (d *logDestination) Send(ctx context.Context, alert *Alert) error {
	level := slog.LevelInfo
	switch alert.Severity {
	case SeverityLow:
		level = slog.LevelInfo
	case SeverityMedium:
		level = slog.LevelWarn
	case SeverityHigh, SeverityCritical:
		level = slog.LevelError
	}

	d.logger.Log(ctx, level, "Security Alert",
		"alert_id", alert.ID,
		"severity", alert.Severity,
		"type", alert.Type,
		"title", alert.Title,
		"description", alert.Description,
		"tags", alert.Tags,
	)

	return nil
}

// webhookDestination sends alerts to a generic webhook
type webhookDestination struct {
	url    string
	client *http.Client
	logger *slog.Logger
}

func (d *webhookDestination) Type() string { return "webhook" }

func (d *webhookDestination) Send(ctx context.Context, alert *Alert) error {
	payload := map[string]interface{}{
		"id":          alert.ID,
		"timestamp":   alert.Timestamp.Format(time.RFC3339),
		"severity":    alert.Severity,
		"type":        alert.Type,
		"title":       alert.Title,
		"description": alert.Description,
		"tags":        alert.Tags,
		"metadata":    alert.Metadata,
	}

	if alert.Event != nil {
		payload["event"] = map[string]interface{}{
			"pid":          alert.Event.PID,
			"uid":          alert.Event.UID,
			"process_name": alert.Event.ProcessName,
			"container_id": alert.Event.ContainerID,
			"pod_name":     alert.Event.PodName,
			"namespace":    alert.Event.PodNamespace,
		}
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal alert: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", d.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// slackDestination sends alerts to Slack
type slackDestination struct {
	webhookURL string
	client     *http.Client
	logger     *slog.Logger
}

func (d *slackDestination) Type() string { return "slack" }

func (d *slackDestination) Send(ctx context.Context, alert *Alert) error {
	color := "#36a64f" // green
	switch alert.Severity {
	case SeverityLow:
		color = "#2196F3" // blue
	case SeverityMedium:
		color = "#FF9800" // orange
	case SeverityHigh:
		color = "#f44336" // red
	case SeverityCritical:
		color = "#9C27B0" // purple
	}

	fields := []map[string]interface{}{
		{"title": "Severity", "value": string(alert.Severity), "short": true},
		{"title": "Type", "value": string(alert.Type), "short": true},
	}

	if alert.Event != nil {
		fields = append(fields,
			map[string]interface{}{"title": "Process", "value": alert.Event.ProcessName, "short": true},
			map[string]interface{}{"title": "PID", "value": fmt.Sprintf("%d", alert.Event.PID), "short": true},
		)

		if alert.Event.ContainerID != "" {
			fields = append(fields,
				map[string]interface{}{"title": "Container", "value": alert.Event.ContainerID[:12], "short": true},
			)
		}
		if alert.Event.PodName != "" {
			fields = append(fields,
				map[string]interface{}{"title": "Pod", "value": alert.Event.PodName, "short": true},
			)
		}
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":       color,
				"title":       fmt.Sprintf("🚨 %s", alert.Title),
				"text":        alert.Description,
				"fields":      fields,
				"footer":      "Telegen Security",
				"footer_icon": "https://opentelemetry.io/img/logos/opentelemetry-logo-nav.png",
				"ts":          alert.Timestamp.Unix(),
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal slack message: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", d.webhookURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send to slack: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("slack returned status %d", resp.StatusCode)
	}

	return nil
}
