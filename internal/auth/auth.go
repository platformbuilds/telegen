// Package auth provides authentication mechanisms for HTTP clients.
package auth

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// AuthType represents the type of authentication.
type AuthType string

const (
	// AuthTypeNone indicates no authentication.
	AuthTypeNone AuthType = "none"
	// AuthTypeBasic indicates HTTP Basic authentication.
	AuthTypeBasic AuthType = "basic"
	// AuthTypeBearer indicates Bearer token authentication.
	AuthTypeBearer AuthType = "bearer"
	// AuthTypeAPIKey indicates API key authentication.
	AuthTypeAPIKey AuthType = "api_key"
)

// Config holds authentication configuration.
type Config struct {
	// Type is the authentication type.
	Type AuthType `yaml:"type" json:"type"`

	// Basic authentication credentials.
	Username string `yaml:"username,omitempty" json:"username,omitempty"`
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// Bearer token authentication.
	Token string `yaml:"token,omitempty" json:"token,omitempty"`
	// TokenFile is a path to a file containing the token (for K8s service accounts).
	TokenFile string `yaml:"token_file,omitempty" json:"token_file,omitempty"`

	// API key authentication.
	APIKey       string `yaml:"api_key,omitempty" json:"api_key,omitempty"`
	APIKeyHeader string `yaml:"api_key_header,omitempty" json:"api_key_header,omitempty"` // Default: X-API-Key

	// TokenRefreshInterval is how often to reload token from TokenFile.
	// Only applies when TokenFile is set. Default: 5 minutes.
	TokenRefreshInterval time.Duration `yaml:"token_refresh_interval,omitempty" json:"token_refresh_interval,omitempty"`
}

// Authenticator applies authentication to HTTP requests.
type Authenticator interface {
	// Apply adds authentication to the request.
	Apply(ctx context.Context, req *http.Request) error
	// Type returns the authentication type.
	Type() AuthType
	// Close releases any resources.
	Close() error
}

// NewAuthenticator creates an authenticator from configuration.
func NewAuthenticator(cfg Config) (Authenticator, error) {
	switch cfg.Type {
	case AuthTypeNone, "":
		return &NoopAuthenticator{}, nil
	case AuthTypeBasic:
		return NewBasicAuthenticator(cfg.Username, cfg.Password)
	case AuthTypeBearer:
		return NewBearerAuthenticator(cfg.Token, cfg.TokenFile, cfg.TokenRefreshInterval)
	case AuthTypeAPIKey:
		return NewAPIKeyAuthenticator(cfg.APIKey, cfg.APIKeyHeader)
	default:
		return nil, fmt.Errorf("unknown auth type: %s", cfg.Type)
	}
}

// NoopAuthenticator is an authenticator that does nothing.
type NoopAuthenticator struct{}

func (a *NoopAuthenticator) Apply(ctx context.Context, req *http.Request) error { return nil }
func (a *NoopAuthenticator) Type() AuthType                                     { return AuthTypeNone }
func (a *NoopAuthenticator) Close() error                                       { return nil }

// BasicAuthenticator implements HTTP Basic authentication.
type BasicAuthenticator struct {
	username string
	password string
}

// NewBasicAuthenticator creates a new Basic authenticator.
func NewBasicAuthenticator(username, password string) (*BasicAuthenticator, error) {
	if username == "" {
		return nil, fmt.Errorf("basic auth: username is required")
	}
	return &BasicAuthenticator{
		username: username,
		password: password,
	}, nil
}

// Apply adds Basic authentication header to the request.
func (a *BasicAuthenticator) Apply(ctx context.Context, req *http.Request) error {
	req.SetBasicAuth(a.username, a.password)
	return nil
}

// Type returns the authentication type.
func (a *BasicAuthenticator) Type() AuthType {
	return AuthTypeBasic
}

// Close releases any resources.
func (a *BasicAuthenticator) Close() error {
	return nil
}

// BearerAuthenticator implements Bearer token authentication.
type BearerAuthenticator struct {
	mu              sync.RWMutex
	staticToken     string
	tokenFile       string
	cachedToken     string
	refreshInterval time.Duration
	lastRefresh     time.Time
	stopCh          chan struct{}
	wg              sync.WaitGroup
}

// NewBearerAuthenticator creates a new Bearer authenticator.
// Either token or tokenFile must be provided.
func NewBearerAuthenticator(token, tokenFile string, refreshInterval time.Duration) (*BearerAuthenticator, error) {
	if token == "" && tokenFile == "" {
		return nil, fmt.Errorf("bearer auth: either token or token_file is required")
	}

	a := &BearerAuthenticator{
		staticToken:     token,
		tokenFile:       tokenFile,
		refreshInterval: refreshInterval,
		stopCh:          make(chan struct{}),
	}

	if refreshInterval == 0 {
		a.refreshInterval = 5 * time.Minute
	}

	// If using tokenFile, load initial token.
	if tokenFile != "" {
		if err := a.refreshToken(); err != nil {
			return nil, fmt.Errorf("bearer auth: failed to read token file: %w", err)
		}

		// Start background refresh.
		a.wg.Add(1)
		go a.refreshLoop()
	}

	return a, nil
}

// Apply adds Bearer token header to the request.
func (a *BearerAuthenticator) Apply(ctx context.Context, req *http.Request) error {
	token := a.getToken()
	if token == "" {
		return fmt.Errorf("bearer auth: no token available")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// Type returns the authentication type.
func (a *BearerAuthenticator) Type() AuthType {
	return AuthTypeBearer
}

// Close stops the background refresh and releases resources.
func (a *BearerAuthenticator) Close() error {
	if a.tokenFile != "" {
		close(a.stopCh)
		a.wg.Wait()
	}
	return nil
}

// getToken returns the current token.
func (a *BearerAuthenticator) getToken() string {
	// If static token is set, use it directly.
	if a.staticToken != "" {
		return a.staticToken
	}

	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.cachedToken
}

// refreshToken reads the token from file.
func (a *BearerAuthenticator) refreshToken() error {
	data, err := os.ReadFile(a.tokenFile)
	if err != nil {
		return err
	}

	token := strings.TrimSpace(string(data))
	if token == "" {
		return fmt.Errorf("token file is empty")
	}

	a.mu.Lock()
	a.cachedToken = token
	a.lastRefresh = time.Now()
	a.mu.Unlock()

	return nil
}

// refreshLoop periodically refreshes the token from file.
func (a *BearerAuthenticator) refreshLoop() {
	defer a.wg.Done()

	ticker := time.NewTicker(a.refreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if err := a.refreshToken(); err != nil {
				// Log error but continue - use cached token.
				// In production, this would use the logger.
			}
		case <-a.stopCh:
			return
		}
	}
}

// APIKeyAuthenticator implements API key authentication via header.
type APIKeyAuthenticator struct {
	apiKey string
	header string
}

// NewAPIKeyAuthenticator creates a new API key authenticator.
func NewAPIKeyAuthenticator(apiKey, header string) (*APIKeyAuthenticator, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("api key auth: api_key is required")
	}
	if header == "" {
		header = "X-API-Key"
	}
	return &APIKeyAuthenticator{
		apiKey: apiKey,
		header: header,
	}, nil
}

// Apply adds API key header to the request.
func (a *APIKeyAuthenticator) Apply(ctx context.Context, req *http.Request) error {
	req.Header.Set(a.header, a.apiKey)
	return nil
}

// Type returns the authentication type.
func (a *APIKeyAuthenticator) Type() AuthType {
	return AuthTypeAPIKey
}

// Close releases any resources.
func (a *APIKeyAuthenticator) Close() error {
	return nil
}
