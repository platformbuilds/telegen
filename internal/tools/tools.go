//go:build tools

// Package tools tracks tool dependencies for code generation.
// This file ensures bpf2go is tracked in go.mod for go generate.
package tools

// This file exists solely to track the bpf2go tool dependency in go.mod.
// The tool is installed and used via:
//   go install github.com/cilium/ebpf/cmd/bpf2go@v0.20.0
//
// Since bpf2go is a main package (program), it cannot be imported directly.
// The dependency is managed through go.mod's tool directive or go install.
