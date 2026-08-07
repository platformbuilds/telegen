package remotewrite

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/prometheus/prometheus/prompb"
)

type TLSConfig struct {
	Enable             bool
	CAFile             string
	CertFile           string
	KeyFile            string
	InsecureSkipVerify bool
}

type Endpoint struct {
	URL         string
	Headers     map[string]string
	Tenant      string
	Timeout     time.Duration
	Compression string // gzip|none
}

type Client struct {
	httpc  *http.Client
	tlsCfg *tls.Config
}

func New() *Client { return &Client{httpc: &http.Client{Timeout: 10 * time.Second}} }

func (c *Client) WithTLS(t TLSConfig) error {
	if !t.Enable {
		return nil
	}
	cfg := &tls.Config{InsecureSkipVerify: t.InsecureSkipVerify}
	if t.CAFile != "" {
		b, err := os.ReadFile(t.CAFile)
		if err != nil {
			return err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(b) {
			return fmt.Errorf("bad ca")
		}
		cfg.RootCAs = pool
	}
	if t.CertFile != "" && t.KeyFile != "" {
		crt, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return err
		}
		cfg.Certificates = []tls.Certificate{crt}
	}
	c.tlsCfg = cfg
	c.httpc.Transport = &http.Transport{TLSClientConfig: cfg}
	return nil
}

func (c *Client) Send(ctx context.Context, wr *prompb.WriteRequest, ep Endpoint) error {
	raw, err := wr.Marshal()
	if err != nil {
		return err
	}
	var body []byte
	if ep.Compression == "gzip" {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		if _, err := gz.Write(raw); err != nil {
			return err
		}
		if err := gz.Close(); err != nil {
			return err
		}
		body = buf.Bytes()
	} else {
		body = raw
	}
	reqTimeout := ep.Timeout
	if reqTimeout <= 0 {
		reqTimeout = 30 * time.Second
	}
	reqCtx, cancel := context.WithTimeout(ctx, reqTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, "POST", ep.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	if ep.Compression == "gzip" {
		req.Header.Set("Content-Encoding", "gzip")
	}
	if ep.Tenant != "" {
		req.Header.Set("X-Scope-OrgID", ep.Tenant)
	}
	for k, v := range ep.Headers {
		req.Header.Set(k, v)
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return err
	}
	if err := resp.Body.Close(); err != nil {
		return err
	}
	if resp.StatusCode/100 == 2 {
		return nil
	}
	return fmt.Errorf("remote_write status %d", resp.StatusCode)
}
