package auth

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNewAuthenticator(t *testing.T) {
	t.Run("none type", func(t *testing.T) {
		auth, err := NewAuthenticator(Config{Type: AuthTypeNone})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if auth.Type() != AuthTypeNone {
			t.Errorf("expected type %v, got %v", AuthTypeNone, auth.Type())
		}
	})

	t.Run("empty type defaults to none", func(t *testing.T) {
		auth, err := NewAuthenticator(Config{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if auth.Type() != AuthTypeNone {
			t.Errorf("expected type %v, got %v", AuthTypeNone, auth.Type())
		}
	})

	t.Run("unknown type", func(t *testing.T) {
		_, err := NewAuthenticator(Config{Type: "unknown"})
		if err == nil {
			t.Error("expected error for unknown type")
		}
	})
}

func TestBasicAuthenticator(t *testing.T) {
	t.Run("valid credentials", func(t *testing.T) {
		auth, err := NewBasicAuthenticator("user", "pass")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		if err := auth.Apply(context.Background(), req); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		user, pass, ok := req.BasicAuth()
		if !ok {
			t.Error("basic auth not set")
		}
		if user != "user" {
			t.Errorf("expected user 'user', got %q", user)
		}
		if pass != "pass" {
			t.Errorf("expected pass 'pass', got %q", pass)
		}
	})

	t.Run("empty username", func(t *testing.T) {
		_, err := NewBasicAuthenticator("", "pass")
		if err == nil {
			t.Error("expected error for empty username")
		}
	})

	t.Run("empty password allowed", func(t *testing.T) {
		auth, err := NewBasicAuthenticator("user", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		if err := auth.Apply(context.Background(), req); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		user, pass, ok := req.BasicAuth()
		if !ok {
			t.Error("basic auth not set")
		}
		if user != "user" || pass != "" {
			t.Errorf("expected user='user' pass='', got user=%q pass=%q", user, pass)
		}
	})

	t.Run("type", func(t *testing.T) {
		auth, _ := NewBasicAuthenticator("user", "pass")
		if auth.Type() != AuthTypeBasic {
			t.Errorf("expected type %v, got %v", AuthTypeBasic, auth.Type())
		}
	})

	t.Run("close", func(t *testing.T) {
		auth, _ := NewBasicAuthenticator("user", "pass")
		if err := auth.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})
}

func TestBearerAuthenticator(t *testing.T) {
	t.Run("static token", func(t *testing.T) {
		auth, err := NewBearerAuthenticator("my-token", "", 0)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer auth.Close()

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		if err := auth.Apply(context.Background(), req); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		authHeader := req.Header.Get("Authorization")
		if authHeader != "Bearer my-token" {
			t.Errorf("expected 'Bearer my-token', got %q", authHeader)
		}
	})

	t.Run("token from file", func(t *testing.T) {
		// Create temp file with token.
		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, "token")
		if err := os.WriteFile(tokenFile, []byte("file-token\n"), 0600); err != nil {
			t.Fatalf("failed to write token file: %v", err)
		}

		auth, err := NewBearerAuthenticator("", tokenFile, 100*time.Millisecond)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer auth.Close()

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		if err := auth.Apply(context.Background(), req); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		authHeader := req.Header.Get("Authorization")
		if authHeader != "Bearer file-token" {
			t.Errorf("expected 'Bearer file-token', got %q", authHeader)
		}
	})

	t.Run("token file refresh", func(t *testing.T) {
		// Create temp file with token.
		tmpDir := t.TempDir()
		tokenFile := filepath.Join(tmpDir, "token")
		if err := os.WriteFile(tokenFile, []byte("initial-token"), 0600); err != nil {
			t.Fatalf("failed to write token file: %v", err)
		}

		auth, err := NewBearerAuthenticator("", tokenFile, 50*time.Millisecond)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		defer auth.Close()

		// Verify initial token.
		req1, _ := http.NewRequest("GET", "http://example.com", nil)
		auth.Apply(context.Background(), req1)
		if req1.Header.Get("Authorization") != "Bearer initial-token" {
			t.Error("initial token not applied")
		}

		// Update token file.
		if err := os.WriteFile(tokenFile, []byte("updated-token"), 0600); err != nil {
			t.Fatalf("failed to update token file: %v", err)
		}

		// Wait for refresh.
		time.Sleep(100 * time.Millisecond)

		// Verify updated token.
		req2, _ := http.NewRequest("GET", "http://example.com", nil)
		auth.Apply(context.Background(), req2)
		if req2.Header.Get("Authorization") != "Bearer updated-token" {
			t.Error("token not refreshed")
		}
	})

	t.Run("missing token and file", func(t *testing.T) {
		_, err := NewBearerAuthenticator("", "", 0)
		if err == nil {
			t.Error("expected error when both token and file are empty")
		}
	})

	t.Run("nonexistent token file", func(t *testing.T) {
		_, err := NewBearerAuthenticator("", "/nonexistent/token", 0)
		if err == nil {
			t.Error("expected error for nonexistent token file")
		}
	})

	t.Run("type", func(t *testing.T) {
		auth, _ := NewBearerAuthenticator("token", "", 0)
		defer auth.Close()
		if auth.Type() != AuthTypeBearer {
			t.Errorf("expected type %v, got %v", AuthTypeBearer, auth.Type())
		}
	})
}

func TestAPIKeyAuthenticator(t *testing.T) {
	t.Run("default header", func(t *testing.T) {
		auth, err := NewAPIKeyAuthenticator("my-api-key", "")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		if err := auth.Apply(context.Background(), req); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		apiKey := req.Header.Get("X-API-Key")
		if apiKey != "my-api-key" {
			t.Errorf("expected 'my-api-key', got %q", apiKey)
		}
	})

	t.Run("custom header", func(t *testing.T) {
		auth, err := NewAPIKeyAuthenticator("my-api-key", "Authorization")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		if err := auth.Apply(context.Background(), req); err != nil {
			t.Fatalf("Apply failed: %v", err)
		}

		apiKey := req.Header.Get("Authorization")
		if apiKey != "my-api-key" {
			t.Errorf("expected 'my-api-key', got %q", apiKey)
		}
	})

	t.Run("empty api key", func(t *testing.T) {
		_, err := NewAPIKeyAuthenticator("", "")
		if err == nil {
			t.Error("expected error for empty api key")
		}
	})

	t.Run("type", func(t *testing.T) {
		auth, _ := NewAPIKeyAuthenticator("key", "")
		if auth.Type() != AuthTypeAPIKey {
			t.Errorf("expected type %v, got %v", AuthTypeAPIKey, auth.Type())
		}
	})

	t.Run("close", func(t *testing.T) {
		auth, _ := NewAPIKeyAuthenticator("key", "")
		if err := auth.Close(); err != nil {
			t.Errorf("Close failed: %v", err)
		}
	})
}

func TestNoopAuthenticator(t *testing.T) {
	auth := &NoopAuthenticator{}

	req, _ := http.NewRequest("GET", "http://example.com", nil)
	if err := auth.Apply(context.Background(), req); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	// Should not modify request.
	if req.Header.Get("Authorization") != "" {
		t.Error("noop should not add authorization header")
	}

	if auth.Type() != AuthTypeNone {
		t.Errorf("expected type %v, got %v", AuthTypeNone, auth.Type())
	}

	if err := auth.Close(); err != nil {
		t.Errorf("Close failed: %v", err)
	}
}
