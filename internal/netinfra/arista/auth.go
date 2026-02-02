// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package arista

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

// Authenticator handles CloudVision authentication
type Authenticator struct {
	config    Config
	client    *http.Client
	log       *slog.Logger
	token     string
	expiresAt time.Time
	mu        sync.RWMutex
}

// AuthResponse represents the CVP authentication response
type AuthResponse struct {
	SessionID string    `json:"sessionId"`
	Cookie    string    `json:"cookie"`
	User      string    `json:"userId"`
	ExpiresAt time.Time `json:"expires,omitempty"`
}

// NewAuthenticator creates a new authenticator
func NewAuthenticator(cfg Config, client *http.Client, log *slog.Logger) *Authenticator {
	return &Authenticator{
		config: cfg,
		client: client,
		log:    log.With("component", "cvp-auth"),
	}
}

// Authenticate performs initial authentication
func (a *Authenticator) Authenticate(ctx context.Context) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	// If token is provided in config (CVaaS), use it directly
	if a.config.Token != "" {
		a.token = a.config.Token
		// Token from config typically doesn't expire within session
		a.expiresAt = time.Now().Add(24 * time.Hour)
		a.log.Info("using configured service account token")
		return nil
	}

	// Otherwise, authenticate with username/password
	return a.authenticateWithCredentials(ctx)
}

// authenticateWithCredentials authenticates using username/password
func (a *Authenticator) authenticateWithCredentials(ctx context.Context) error {
	url := fmt.Sprintf("%s/cvpservice/login/authenticate.do", a.config.CVPURL)

	payload := map[string]string{
		"userId":   a.config.Username,
		"password": a.config.Password,
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
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	var authResp AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	if authResp.SessionID == "" {
		return fmt.Errorf("no session ID in auth response")
	}

	a.token = authResp.SessionID
	// CVP sessions typically expire in 24 hours, refresh before that
	a.expiresAt = time.Now().Add(12 * time.Hour)

	a.log.Info("successfully authenticated with CVP", "user", a.config.Username)
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

	return a.Authenticate(ctx)
}

// isTokenValid checks if current token is still valid
func (a *Authenticator) isTokenValid() bool {
	if a.token == "" {
		return false
	}
	// Add 5 minute buffer before expiry
	return time.Now().Add(5 * time.Minute).Before(a.expiresAt)
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
	// For CVP, we need to re-authenticate
	// CVP doesn't have a token refresh endpoint like OAuth
	return a.Authenticate(ctx)
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

	// Try Bearer token first (CVaaS style)
	if a.config.Token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	} else {
		// Fall back to session cookie style
		req.Header.Set("Cookie", fmt.Sprintf("access_token=%s", token))
	}

	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}
