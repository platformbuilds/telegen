// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package kafka

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
)

// CreateTLSConfig creates a TLS configuration from the provided settings
func CreateTLSConfig(tlsCfg *struct {
	Enable             bool
	CAFile             string
	CertFile           string
	KeyFile            string
	InsecureSkipVerify bool
}) (*tls.Config, error) {
	if tlsCfg == nil || !tlsCfg.Enable {
		return nil, nil
	}

	config := &tls.Config{
		InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
	}

	// Load CA certificate if provided
	if tlsCfg.CAFile != "" {
		caCert, err := os.ReadFile(tlsCfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		config.RootCAs = caCertPool
	}

	// Load client certificate and key if provided
	if tlsCfg.CertFile != "" && tlsCfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load client certificate: %w", err)
		}
		config.Certificates = []tls.Certificate{cert}
	}

	return config, nil
}
