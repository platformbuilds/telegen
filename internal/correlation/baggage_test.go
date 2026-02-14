// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package correlation

import (
	"context"
	"testing"
)

func TestParseBaggage(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected map[string]string
		wantErr  bool
	}{
		{
			name:  "empty baggage",
			input: "",
			expected: map[string]string{},
		},
		{
			name:  "single member",
			input: "key1=value1",
			expected: map[string]string{
				"key1": "value1",
			},
		},
		{
			name:  "multiple members",
			input: "key1=value1,key2=value2,key3=value3",
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
				"key3": "value3",
			},
		},
		{
			name:  "percent encoded value",
			input: "key1=hello%20world",
			expected: map[string]string{
				"key1": "hello world",
			},
		},
		{
			name:  "with properties",
			input: "key1=value1;property1;property2=val",
			expected: map[string]string{
				"key1": "value1",
			},
		},
		{
			name:  "with spaces",
			input: " key1 = value1 , key2 = value2 ",
			expected: map[string]string{
				"key1": "value1",
				"key2": "value2",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bag, err := ParseBaggage(tt.input)
			if err != nil {
				if !tt.wantErr {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}

			result := bag.ToMap()
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d members, got %d", len(tt.expected), len(result))
			}

			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("expected %s=%s, got %s=%s", k, v, k, result[k])
				}
			}
		})
	}
}

func TestBaggageOperations(t *testing.T) {
	bag := NewBaggage()

	// Test Set
	err := bag.Set("key1", "value1")
	if err != nil {
		t.Fatalf("failed to set: %v", err)
	}

	// Test Get
	val, ok := bag.Get("key1")
	if !ok || val != "value1" {
		t.Errorf("expected value1, got %s", val)
	}

	// Test overwrite
	err = bag.Set("key1", "value2")
	if err != nil {
		t.Fatalf("failed to overwrite: %v", err)
	}

	val, ok = bag.Get("key1")
	if !ok || val != "value2" {
		t.Errorf("expected value2, got %s", val)
	}

	// Test Delete
	bag.Delete("key1")
	_, ok = bag.Get("key1")
	if ok {
		t.Error("expected key1 to be deleted")
	}
}

func TestBaggageString(t *testing.T) {
	bag := NewBaggage()
	_ = bag.Set("key1", "value1")
	_ = bag.Set("key2", "hello world")

	str := bag.String()
	if str == "" {
		t.Error("expected non-empty string")
	}

	// Parse back
	bag2, err := ParseBaggage(str)
	if err != nil {
		t.Fatalf("failed to parse back: %v", err)
	}

	val, ok := bag2.Get("key1")
	if !ok || val != "value1" {
		t.Errorf("expected value1, got %s", val)
	}

	val, ok = bag2.Get("key2")
	if !ok || val != "hello world" {
		t.Errorf("expected hello world, got %s", val)
	}
}

func TestBaggageContext(t *testing.T) {
	bag := NewBaggage()
	_ = bag.Set("user.id", "12345")

	ctx := ContextWithBaggage(context.Background(), bag)

	retrieved := BaggageFromContext(ctx)
	if retrieved == nil {
		t.Fatal("expected baggage from context")
	}

	val, ok := retrieved.Get("user.id")
	if !ok || val != "12345" {
		t.Errorf("expected 12345, got %s", val)
	}
}

func TestW3CBaggagePropagator(t *testing.T) {
	prop := NewW3CBaggagePropagator()

	// Create context with baggage
	bag := NewBaggage()
	_ = bag.Set("user.id", "12345")
	_ = bag.Set("tenant", "acme")

	ctx := ContextWithBaggage(context.Background(), bag)

	// Inject
	carrier := MapCarrier{}
	prop.Inject(ctx, carrier)

	baggageHeader := carrier.Get("baggage")
	if baggageHeader == "" {
		t.Fatal("expected baggage header to be set")
	}

	// Extract
	ctx2 := context.Background()
	ctx2 = prop.Extract(ctx2, carrier)

	retrieved := BaggageFromContext(ctx2)
	if retrieved == nil {
		t.Fatal("expected baggage from extracted context")
	}

	val, ok := retrieved.Get("user.id")
	if !ok || val != "12345" {
		t.Errorf("expected 12345, got %s", val)
	}
}

func TestMergeBaggage(t *testing.T) {
	bag1 := NewBaggage()
	_ = bag1.Set("key1", "value1")
	_ = bag1.Set("key2", "value2")

	bag2 := NewBaggage()
	_ = bag2.Set("key2", "overwritten")
	_ = bag2.Set("key3", "value3")

	merged := MergeBaggage(bag1, bag2)

	// Check key1 from bag1
	val, ok := merged.Get("key1")
	if !ok || val != "value1" {
		t.Errorf("expected value1, got %s", val)
	}

	// Check key2 is overwritten by bag2
	val, ok = merged.Get("key2")
	if !ok || val != "overwritten" {
		t.Errorf("expected overwritten, got %s", val)
	}

	// Check key3 from bag2
	val, ok = merged.Get("key3")
	if !ok || val != "value3" {
		t.Errorf("expected value3, got %s", val)
	}
}

func TestValidateBaggageKey(t *testing.T) {
	validKeys := []string{
		"key",
		"key1",
		"key-name",
		"key_name",
		"Key",
	}

	for _, key := range validKeys {
		if !ValidateBaggageKey(key) {
			t.Errorf("expected %s to be valid", key)
		}
	}

	invalidKeys := []string{
		"",
		"key name",
		"key=value",
	}

	for _, key := range invalidKeys {
		if ValidateBaggageKey(key) {
			t.Errorf("expected %s to be invalid", key)
		}
	}
}
