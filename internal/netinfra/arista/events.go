// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package arista

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// EventSubscriber subscribes to CloudVision events for configuration changes
type EventSubscriber struct {
	cvp    *CloudVisionCollector
	log    *slog.Logger
	conn   *websocket.Conn
	events chan *CVPEvent

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.RWMutex
	running bool
}

// CVPEvent represents a CloudVision event
type CVPEvent struct {
	Type      string                 `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	DeviceID  string                 `json:"deviceId,omitempty"`
	Key       string                 `json:"key,omitempty"`
	Data      map[string]interface{} `json:"data,omitempty"`
}

// ConfigChangeEvent represents a configuration change event
type ConfigChangeEvent struct {
	DeviceID    string    `json:"deviceId"`
	ChangeTime  time.Time `json:"changeTime"`
	User        string    `json:"user"`
	Session     string    `json:"session"`
	DiffSummary string    `json:"diffSummary"`
	ConfigLines int       `json:"configLines"`
}

// NewEventSubscriber creates a new event subscriber
func NewEventSubscriber(cvp *CloudVisionCollector) *EventSubscriber {
	return &EventSubscriber{
		cvp:    cvp,
		log:    cvp.log.With("component", "events"),
		events: make(chan *CVPEvent, 1000),
	}
}

// Start starts the event subscriber
func (e *EventSubscriber) Start(ctx context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.running {
		return nil
	}

	e.ctx, e.cancel = context.WithCancel(ctx)

	// Start WebSocket connection
	e.wg.Add(1)
	go e.subscribeLoop()

	e.running = true
	e.log.Info("event subscriber started")
	return nil
}

// Stop stops the event subscriber
func (e *EventSubscriber) Stop() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if !e.running {
		return
	}

	e.cancel()

	if e.conn != nil {
		e.conn.Close()
	}

	e.wg.Wait()
	close(e.events)

	e.running = false
	e.log.Info("event subscriber stopped")
}

// Events returns the events channel
func (e *EventSubscriber) Events() <-chan *CVPEvent {
	return e.events
}

// subscribeLoop maintains the WebSocket connection
func (e *EventSubscriber) subscribeLoop() {
	defer e.wg.Done()

	for {
		select {
		case <-e.ctx.Done():
			return
		default:
		}

		err := e.subscribe()
		if err != nil {
			e.log.Warn("event subscription error, retrying", "error", err)
			select {
			case <-e.ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}
}

// subscribe establishes WebSocket connection and receives events
func (e *EventSubscriber) subscribe() error {
	// Construct WebSocket URL
	wsURL := fmt.Sprintf("wss://%s/api/v3/events/subscribe", e.cvp.GetBaseURL()[8:]) // Remove https://

	// Create dialer with headers
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
	}

	// Create headers with authentication
	headers := make(map[string][]string)
	token := e.cvp.GetToken()
	if token != "" {
		headers["Authorization"] = []string{"Bearer " + token}
	}

	conn, _, err := dialer.DialContext(e.ctx, wsURL, headers)
	if err != nil {
		return fmt.Errorf("failed to connect to event stream: %w", err)
	}
	e.conn = conn
	defer conn.Close()

	// Send subscription message
	subscribeMsg := map[string]interface{}{
		"type": "subscribe",
		"topics": []string{
			"configlet",
			"device",
			"task",
			"container",
			"changecontrol",
		},
	}

	if err := conn.WriteJSON(subscribeMsg); err != nil {
		return fmt.Errorf("failed to send subscribe message: %w", err)
	}

	e.log.Info("subscribed to CVP events")

	// Read events
	for {
		select {
		case <-e.ctx.Done():
			return nil
		default:
		}

		_, message, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("failed to read message: %w", err)
		}

		var event CVPEvent
		if err := json.Unmarshal(message, &event); err != nil {
			e.log.Warn("failed to parse event", "error", err)
			continue
		}

		event.Timestamp = time.Now()

		select {
		case e.events <- &event:
		default:
			e.log.Warn("event channel full, dropping event")
		}
	}
}

// GetConfigChanges fetches recent configuration changes
func (e *EventSubscriber) GetConfigChanges(ctx context.Context, since time.Time) ([]ConfigChangeEvent, error) {
	url := fmt.Sprintf("%s/cvpservice/configlet/getConfigletAudit.do", e.cvp.GetBaseURL())

	req, err := e.cvp.auth.CreateAuthenticatedRequest(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	resp, err := e.cvp.GetClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Data []ConfigChangeEvent `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	// Filter by time
	var filtered []ConfigChangeEvent
	for _, change := range result.Data {
		if change.ChangeTime.After(since) {
			filtered = append(filtered, change)
		}
	}

	return filtered, nil
}

// EventHandler is a callback for processing events
type EventHandler func(event *CVPEvent)

// OnEvent registers an event handler
func (e *EventSubscriber) OnEvent(handler EventHandler) {
	go func() {
		for event := range e.events {
			handler(event)
		}
	}()
}
