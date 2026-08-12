// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

// Config configures the ONTAP REST client.
type Config struct {
	BaseURL    string
	Timeout    time.Duration
	VerifySSL  bool
	Username   string
	Password   string
	AuthToken  string
	AuthStyle  string // basic | bearer | certificate
	GCNVMode   bool
	CAFile     string
	ClientCert string
	ClientKey  string
}

// Metadata tracks request volume for collector health.
type Metadata struct {
	BytesRx  atomic.Uint64
	NumCalls atomic.Uint64
}

// Client is an ONTAP REST HTTP client with pagination.
type Client struct {
	http    *http.Client
	baseURL string
	cfg     Config
	Meta    Metadata
}

type recordsEnvelope struct {
	Records []json.RawMessage `json:"records"`
	Links   struct {
		Next struct {
			Href string `json:"href"`
		} `json:"next"`
	} `json:"_links"`
}

// New creates an ONTAP REST client.
func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, fmt.Errorf("base URL is required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	base := strings.TrimRight(cfg.BaseURL, "/") + "/"

	tlsCfg := &tls.Config{InsecureSkipVerify: !cfg.VerifySSL} //nolint:gosec // operator-controlled
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("failed to parse CA file %s", cfg.CAFile)
		}
		tlsCfg.RootCAs = pool
	}
	if cfg.ClientCert != "" && cfg.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	}

	return &Client{
		http: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				TLSClientConfig: tlsCfg,
			},
		},
		baseURL: base,
		cfg:     cfg,
	}, nil
}

func (c *Client) rewriteFields(path string) string {
	if !c.cfg.GCNVMode {
		return path
	}
	path = strings.ReplaceAll(path, "?fields=", "?ontap_fields=")
	path = strings.ReplaceAll(path, "&fields=", "&ontap_fields=")
	return path
}

func (c *Client) unwrapGCNV(data []byte) []byte {
	if !c.cfg.GCNVMode || len(data) == 0 {
		return data
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(data, &env); err != nil {
		return data
	}
	if body, ok := env["body"]; ok {
		return body
	}
	return data
}

func (c *Client) authorize(req *http.Request) {
	req.Header.Set("Accept", "application/json")
	if c.cfg.AuthToken != "" || strings.EqualFold(c.cfg.AuthStyle, "bearer") {
		token := c.cfg.AuthToken
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return
	}
	if c.cfg.Username != "" {
		tok := base64.StdEncoding.EncodeToString([]byte(c.cfg.Username + ":" + c.cfg.Password))
		req.Header.Set("Authorization", "Basic "+tok)
	}
}

// GetBytes performs a GET and returns raw JSON body.
func (c *Client) GetBytes(ctx context.Context, pathOrURL string) ([]byte, error) {
	pathOrURL = c.rewriteFields(pathOrURL)
	var full string
	if strings.HasPrefix(pathOrURL, "http://") || strings.HasPrefix(pathOrURL, "https://") {
		full = pathOrURL
	} else {
		full = c.baseURL + strings.TrimPrefix(pathOrURL, "/")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, full, nil)
	if err != nil {
		return nil, err
	}
	c.authorize(req)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	c.Meta.BytesRx.Add(uint64(len(body)))
	c.Meta.NumCalls.Add(1)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &APIError{StatusCode: resp.StatusCode, Message: string(body)}
	}
	return c.unwrapGCNV(body), nil
}

// FetchAll paginates through all records for a list endpoint.
func (c *Client) FetchAll(ctx context.Context, path string) ([]json.RawMessage, error) {
	var all []json.RawMessage
	next := path
	for next != "" {
		body, err := c.GetBytes(ctx, next)
		if err != nil {
			return nil, err
		}
		var env recordsEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			// single object (no records array)
			trimmed := bytes.TrimSpace(body)
			if len(trimmed) > 0 && trimmed[0] == '{' {
				all = append(all, json.RawMessage(body))
				return all, nil
			}
			return nil, fmt.Errorf("decode records: %w", err)
		}
		all = append(all, env.Records...)
		next = c.normalizeNext(env.Links.Next.Href)
	}
	return all, nil
}

// FetchAllStream calls fn for each page of records.
func (c *Client) FetchAllStream(ctx context.Context, path string, fn func(records []json.RawMessage) error) error {
	next := path
	for next != "" {
		body, err := c.GetBytes(ctx, next)
		if err != nil {
			return err
		}
		var env recordsEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			trimmed := bytes.TrimSpace(body)
			if len(trimmed) > 0 && trimmed[0] == '{' {
				return fn([]json.RawMessage{json.RawMessage(body)})
			}
			return fmt.Errorf("decode records: %w", err)
		}
		if len(env.Records) > 0 {
			if err := fn(env.Records); err != nil {
				return err
			}
		}
		next = c.normalizeNext(env.Links.Next.Href)
	}
	return nil
}

func (c *Client) normalizeNext(href string) string {
	if href == "" {
		return ""
	}
	if strings.HasPrefix(href, "http://") || strings.HasPrefix(href, "https://") {
		u, err := url.Parse(href)
		if err != nil {
			return href
		}
		// Keep path+query relative to base host
		return strings.TrimPrefix(u.Path, "/") + func() string {
			if u.RawQuery == "" {
				return ""
			}
			return "?" + u.RawQuery
		}()
	}
	return strings.TrimPrefix(href, "/")
}

// SetAuthToken updates bearer token (e.g. refresh).
func (c *Client) SetAuthToken(token string) {
	c.cfg.AuthToken = token
}

// APIError is a non-2xx ONTAP response.
type APIError struct {
	StatusCode int
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("ONTAP API error %d: %s", e.StatusCode, e.Message)
}
