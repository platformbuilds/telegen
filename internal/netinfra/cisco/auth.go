// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package cisco

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Authenticator handles APIC authentication
type Authenticator struct {
	config    Config
	client    *http.Client
	log       *slog.Logger
	token     string
	expiresAt time.Time
	mu        sync.RWMutex
}

// AuthResponse represents the APIC authentication response
type AuthResponse struct {
	Imdata []struct {
		AAALogin struct {
			Attributes struct {
				Token             string `json:"token"`
				RefreshTimeoutSec string `json:"refreshTimeoutSeconds"`
				MaximumLifetime   string `json:"maximumLifetimeSeconds"`
				FirstName         string `json:"firstName"`
				LastName          string `json:"lastName"`
			} `json:"attributes"`
		} `json:"aaaLogin"`
	} `json:"imdata"`
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(cfg Config, client *http.Client, log *slog.Logger) *Authenticator {
	return &Authenticator{
		config: cfg,
		client: client,
		log:    log.With("component", "aci-auth"),
	}
}

// Authenticate performs initial authentication
func (a *Authenticator) Authenticate(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	return a.authenticateWithCredentials(ctx)
}

// authenticateWithCredentials authenticates using username/password
func (a *Authenticator) authenticateWithCredentials(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/aaaLogin.json", a.config.APICURL)

	// Build authentication payload
	payload := map[string]interface{}{
		"aaaUser": map[string]interface{}{
			"attributes": map[string]string{
				"name": a.config.Username,
				"pwd":  a.config.Password,
			},
		},
	}

	// Add domain if specified
	if a.config.Domain != "" {
		payload["aaaUser"].(map[string]interface{})["attributes"].(map[string]string)["domain"] = a.config.Domain
	}

	jsonBody, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal auth payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("failed to create auth request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("authentication request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	if len(authResp.Imdata) == 0 {
		return fmt.Errorf("no authentication data in response")
	}

	token := authResp.Imdata[0].AAALogin.Attributes.Token
	if token == "" {
		return fmt.Errorf("no token in auth response")
	}

	a.token = token
	// APIC tokens typically expire in 600 seconds (10 minutes)
	// Refresh before that
	a.expiresAt = time.Now().Add(8 * time.Minute)

	a.log.Info("successfully authenticated with APIC", "user", a.config.Username)
	return nil
}

// EnsureAuthenticated checks if token is valid and refreshes if needed
func (a *Authenticator) EnsureAuthenticated(ctx context.Context) error {
	a.mu.RLock()
	valid := a.isTokenValid()
	a.mu.RUnlock()

	if valid {
		return nil
	}

	return a.RefreshToken(ctx)
}

// isTokenValid checks if current token is still valid
func (a *Authenticator) isTokenValid() bool {
	if a.token == "" {
		return false
	}
	// Add 1 minute buffer before expiry
	return time.Now().Add(1 * time.Minute).Before(a.expiresAt)
}

// GetToken returns the current authentication token
func (a *Authenticator) GetToken() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.token
}

// Invalidate marks the token as invalid
func (a *Authenticator) Invalidate() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.token = ""
	a.expiresAt = time.Time{}
}

// RefreshToken refreshes the authentication token
func (a *Authenticator) RefreshToken(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Try to refresh first
	if a.token != "" {
		err := a.refreshExistingToken(ctx)
		if err == nil {
			return nil
		}
		a.log.Debug("token refresh failed, re-authenticating", "error", err)
	}

	// Fall back to full re-authentication
	return a.authenticateWithCredentials(ctx)
}

// refreshExistingToken refreshes the current token
func (a *Authenticator) refreshExistingToken(ctx context.Context) error {
	url := fmt.Sprintf("%s/api/aaaRefresh.json", a.config.APICURL)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Cookie", fmt.Sprintf("APIC-cookie=%s", a.token))
	req.Header.Set("Accept", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("refresh failed with status: %d", resp.StatusCode)
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return err
	}

	if len(authResp.Imdata) == 0 {
		return fmt.Errorf("no data in refresh response")
	}

	token := authResp.Imdata[0].AAALogin.Attributes.Token
	if token == "" {
		return fmt.Errorf("no token in refresh response")
	}

	a.token = token
	a.expiresAt = time.Now().Add(8 * time.Minute)

	a.log.Debug("token refreshed successfully")
	return nil
}

// CreateAuthenticatedRequest creates an HTTP request with authentication
func (a *Authenticator) CreateAuthenticatedRequest(ctx context.Context, method, url string, body []byte) (*http.Request, error) {
	var req *http.Request
	var err error

	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, url, bytes.NewReader(body))
	} else {
		req, err = http.NewRequestWithContext(ctx, method, url, nil)
	}
	if err != nil {
		return nil, err
	}

	a.mu.RLock()
	token := a.token
	a.mu.RUnlock()

	req.Header.Set("Cookie", fmt.Sprintf("APIC-cookie=%s", token))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}
