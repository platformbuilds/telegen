// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package jsonpath

import (
	"encoding/json"
	"strconv"
	"strings"
)

// Get returns a nested value from JSON using dot paths (Harvest/gjson-like subset).
func Get(data json.RawMessage, path string) (any, bool) {
	if len(data) == 0 || path == "" {
		return nil, false
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, false
	}
	return dig(v, strings.Split(path, "."))
}

// GetString returns string form of a path.
func GetString(data json.RawMessage, path string) (string, bool) {
	v, ok := Get(data, path)
	if !ok || v == nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(t), true
	case json.Number:
		return t.String(), true
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return "", false
		}
		return string(b), true
	}
}

// GetFloat returns numeric value.
func GetFloat(data json.RawMessage, path string) (float64, bool) {
	v, ok := Get(data, path)
	if !ok || v == nil {
		return 0, false
	}
	switch t := v.(type) {
	case float64:
		return t, true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(t, 64)
		return f, err == nil
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	default:
		return 0, false
	}
}

func dig(v any, parts []string) (any, bool) {
	if len(parts) == 0 {
		return v, true
	}
	key := parts[0]
	rest := parts[1:]
	switch m := v.(type) {
	case map[string]any:
		child, ok := m[key]
		if !ok {
			return nil, false
		}
		return dig(child, rest)
	case []any:
		idx, err := strconv.Atoi(key)
		if err != nil || idx < 0 || idx >= len(m) {
			return nil, false
		}
		return dig(m[idx], rest)
	default:
		return nil, false
	}
}
