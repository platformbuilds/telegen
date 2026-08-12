// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package jsonpath_test

import (
	"encoding/json"
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/jsonpath"
)

func TestGetStringOverTemperatureAllShapes(t *testing.T) {
	for _, tc := range []struct {
		body string
		want string
	}{
		{`{"controller":{"over_temperature":true}}`, "true"},
		{`{"controller":{"over_temperature":false}}`, "false"},
		{`{"controller":{"over_temperature":"true"}}`, "true"},
		{`{"controller":{"over_temperature":"normal"}}`, "normal"},
		{`{"controller":{"over_temperature":"over"}}`, "over"},
	} {
		got, ok := jsonpath.GetString(json.RawMessage(tc.body), "controller.over_temperature")
		if !ok {
			t.Fatalf("GetString not ok for %s", tc.body)
		}
		if got != tc.want {
			t.Errorf("GetString(%s) = %q, want %q", tc.body, got, tc.want)
		}
	}
}

func TestGetFloatCrossVolumeDedupeSavingsAllShapes(t *testing.T) {
	for _, tc := range []struct {
		body string
		want float64
	}{
		{`{"space":{"efficiency":{"cross_volume_dedupe_savings":1.5}}}`, 1.5},
		{`{"space":{"efficiency":{"cross_volume_dedupe_savings":"1.5"}}}`, 1.5},
		{`{"space":{"efficiency":{"cross_volume_dedupe_savings":true}}}`, 1},
		{`{"space":{"efficiency":{"cross_volume_dedupe_savings":false}}}`, 0},
	} {
		got, ok := jsonpath.GetFloat(json.RawMessage(tc.body), "space.efficiency.cross_volume_dedupe_savings")
		if !ok {
			t.Fatalf("GetFloat not ok for %s", tc.body)
		}
		if got != tc.want {
			t.Errorf("GetFloat(%s) = %v, want %v", tc.body, got, tc.want)
		}
	}
}

func TestGetMissingPathIsNotAnError(t *testing.T) {
	if _, ok := jsonpath.GetFloat(json.RawMessage(`{"space":{}}`), "space.efficiency.savings"); ok {
		t.Fatal("missing path should report ok=false")
	}
	if _, ok := jsonpath.GetString(json.RawMessage(`{"controller":{}}`), "controller.over_temperature"); ok {
		t.Fatal("missing path should report ok=false")
	}
}
