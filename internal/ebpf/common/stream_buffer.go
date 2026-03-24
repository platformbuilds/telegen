// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import "sync"

// StreamBuffer is a byte-position-indexed rolling buffer for TCP stream reassembly.
// It handles out-of-order eBPF events by slotting data at the exact logical stream
// offset. Head() returns only the contiguous prefix, stopping at the first gap.
//
// Design mirrors Pixie's DataStreamBuffer (protocols/common/data_stream_buffer.h),
// using the simpler "always contiguous" implementation.
type StreamBuffer struct {
	mu       sync.Mutex
	buf      []byte
	basePos  uint64 // stream-absolute offset of buf[0]
	valid    uint64 // number of valid (filled) bytes starting at buf[0]
	gapMap   map[uint64][]byte // pending out-of-order chunks keyed by stream offset
	maxCap   uint64
	maxGap   uint64
}

// NewStreamBuffer creates a new StreamBuffer.
// maxCap is the maximum bytes held before old data is dropped.
// maxGap is the maximum allowed gap size; gaps larger than this cause the head to advance.
func NewStreamBuffer(maxCap, maxGap uint64) *StreamBuffer {
	return &StreamBuffer{
		buf:    make([]byte, 0, maxCap),
		gapMap: make(map[uint64][]byte),
		maxCap: maxCap,
		maxGap: maxGap,
	}
}

// Add inserts data at the given stream-absolute position.
// Out-of-order chunks are stashed and spliced in when the gap closes.
func (s *StreamBuffer) Add(pos uint64, data []byte) {
	if len(data) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	// Stale data that is before our current base — drop it.
	if pos < s.basePos {
		overlap := s.basePos - pos
		if uint64(len(data)) <= overlap {
			return // entirely old
		}
		data = data[overlap:]
		pos = s.basePos
	}

	expectedNext := s.basePos + uint64(len(s.buf))

	if pos == expectedNext {
		// In-order: append directly.
		s.buf = append(s.buf, data...)
		// Try to apply any pending out-of-order chunks.
		s.mergePending()
	} else {
		// Out-of-order: stash for later.
		chunk := make([]byte, len(data))
		copy(chunk, data)
		s.gapMap[pos] = chunk
	}

	// If the buffer has grown beyond capacity, drop the oldest bytes.
	if uint64(len(s.buf)) > s.maxCap {
		drop := uint64(len(s.buf)) - s.maxCap
		s.buf = s.buf[drop:]
		s.basePos += drop
	}
}

// mergePending tries to splice any stashed out-of-order chunks into the contiguous tail.
func (s *StreamBuffer) mergePending() {
	for {
		next := s.basePos + uint64(len(s.buf))
		chunk, ok := s.gapMap[next]
		if !ok {
			break
		}
		s.buf = append(s.buf, chunk...)
		delete(s.gapMap, next)
	}
}

// Head returns the current contiguous prefix of the stream as a byte slice.
// The slice is valid until the next call to Add or RemovePrefix.
func (s *StreamBuffer) Head() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf
}

// RemovePrefix consumes the first n bytes from the head of the buffer.
func (s *StreamBuffer) RemovePrefix(n int) {
	if n <= 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if n > len(s.buf) {
		n = len(s.buf)
	}
	s.buf = s.buf[n:]
	s.basePos += uint64(n)
}

// BasePos returns the stream-absolute offset of the first byte in Head().
func (s *StreamBuffer) BasePos() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.basePos
}

// Size returns the number of contiguous bytes currently buffered.
func (s *StreamBuffer) Size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.buf)
}

// Reset clears all buffered data.
func (s *StreamBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf = s.buf[:0]
	s.gapMap = make(map[uint64][]byte)
	s.basePos = 0
}

// AdvancePastGap advances the base position past maxGap bytes of gap, allowing
// the parser to attempt re-synchronisation after a large loss event.
func (s *StreamBuffer) AdvancePastGap() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.buf) == 0 && len(s.gapMap) > 0 {
		// Find the smallest pending chunk position and jump to it.
		var minPos uint64
		first := true
		for pos := range s.gapMap {
			if first || pos < minPos {
				minPos = pos
				first = false
			}
		}
		if minPos > s.basePos+s.maxGap {
			s.basePos = minPos
			s.mergePending()
		}
	}
}
