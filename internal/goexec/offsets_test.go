// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package goexec

import (
	"testing"
	"time"

	"github.com/mirastacklabs-ai/telegen/internal/testutil"
)

// TestProcessNotFound tests that InspectOffsets process exits on context cancellation
// even if the target process wasn't found
func TestProcessNotFound(t *testing.T) {
	finish := make(chan struct{})
	go func() {
		defer close(finish)
		if _, err := InspectOffsets(nil, nil); err == nil {
			t.Log("was expecting error in InspectOffsets")
		}
	}()
	testutil.ReadChannel(t, finish, 5*time.Second)
}

func TestOffsetsHasGoChannelOffsets(t *testing.T) {
	full := &Offsets{
		Field: FieldOffsets{
			HchanQcountPos:   uint64(1),
			HchanDataqsizPos: uint64(2),
			HchanSendxPos:    uint64(3),
			HchanRecvxPos:    uint64(4),
		},
	}
	if !full.HasGoChannelOffsets() {
		t.Fatalf("expected complete hchan offsets to be reported as present")
	}

	missing := &Offsets{
		Field: FieldOffsets{
			HchanQcountPos: uint64(1),
			HchanSendxPos:  uint64(3),
		},
	}
	if missing.HasGoChannelOffsets() {
		t.Fatalf("expected missing hchan offsets to be reported as absent")
	}

	if (*Offsets)(nil).HasGoChannelOffsets() {
		t.Fatalf("nil offsets should not report channel offsets")
	}
}
