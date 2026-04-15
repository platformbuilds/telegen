//go:build !linux || !cgo

package host

import "github.com/prometheus/prometheus/prompb"

// appendGPU is a no-op on non-Linux platforms or when CGO is disabled.
func (c *Collector) appendGPU(_ *prompb.WriteRequest) {}
