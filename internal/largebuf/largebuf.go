// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package largebuf // import "github.com/mirastacklabs-ai/telegen/internal/largebuf"

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// LargeBuffer is a minimal contiguous byte buffer used by protocol parsers.
// It intentionally keeps API parity with OBI's parser-facing methods.
type LargeBuffer struct {
	data []byte
}

func NewLargeBuffer() *LargeBuffer {
	return &LargeBuffer{}
}

// NewLargeBufferFrom wraps the provided slice without copying.
func NewLargeBufferFrom(b []byte) *LargeBuffer {
	return &LargeBuffer{data: b}
}

// AppendChunk appends a copy of b to the backing buffer.
func (lb *LargeBuffer) AppendChunk(b []byte) {
	if len(b) == 0 {
		return
	}
	cp := make([]byte, len(b))
	copy(cp, b)
	lb.data = append(lb.data, cp...)
}

func (lb *LargeBuffer) Len() int {
	return len(lb.data)
}

func (lb *LargeBuffer) IsEmpty() bool {
	return len(lb.data) == 0
}

func (lb *LargeBuffer) UnsafeView() []byte {
	return lb.data
}

// CloneBytes returns an owned copy of the current buffer.
func (lb *LargeBuffer) CloneBytes() []byte {
	if len(lb.data) == 0 {
		return nil
	}
	out := make([]byte, len(lb.data))
	copy(out, lb.data)
	return out
}

func (lb *LargeBuffer) UnsafeViewAt(absOff, n int) ([]byte, error) {
	if n < 0 || absOff < 0 || absOff+n > len(lb.data) {
		return nil, fmt.Errorf("largebuf: view [%d,%d) out of range [0,%d)", absOff, absOff+n, len(lb.data))
	}
	return lb.data[absOff : absOff+n], nil
}

func (lb *LargeBuffer) U8At(absOff int) (uint8, error) {
	b, err := lb.UnsafeViewAt(absOff, 1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (lb *LargeBuffer) U16BEAt(absOff int) (uint16, error) {
	b, err := lb.UnsafeViewAt(absOff, 2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

func (lb *LargeBuffer) NewReader() LargeBufferReader {
	return LargeBufferReader{lb: lb, start: 0, end: len(lb.data)}
}

func (lb *LargeBuffer) NewLimitedReader(offset, end int) (LargeBufferReader, error) {
	if offset < 0 || end < offset || end > len(lb.data) {
		return LargeBufferReader{}, fmt.Errorf("largebuf: invalid limited reader range [%d,%d) for len=%d", offset, end, len(lb.data))
	}
	return LargeBufferReader{lb: lb, start: offset, end: end}, nil
}

type LargeBufferReader struct {
	lb    *LargeBuffer
	start int
	end   int
	off   int
}

func (r *LargeBufferReader) Reset() {
	r.off = 0
}

func (r *LargeBufferReader) ReadOffset() int {
	return r.start + r.off
}

func (r *LargeBufferReader) Remaining() int {
	return r.end - r.ReadOffset()
}

func (r *LargeBufferReader) ReadN(n int) ([]byte, error) {
	if n < 0 || n > r.Remaining() {
		return nil, fmt.Errorf("largebuf: cannot read %d bytes (remaining=%d)", n, r.Remaining())
	}
	if n == 0 {
		return nil, nil
	}
	start := r.ReadOffset()
	r.off += n
	return r.lb.data[start : start+n], nil
}

func (r *LargeBufferReader) Skip(n int) error {
	if n < 0 || n > r.Remaining() {
		return fmt.Errorf("largebuf: cannot skip %d bytes (remaining=%d)", n, r.Remaining())
	}
	r.off += n
	return nil
}

func (r *LargeBufferReader) IndexByte(c byte) int {
	rel := bytes.IndexByte(r.lb.data[r.ReadOffset():r.end], c)
	return rel
}

func (r *LargeBufferReader) Bytes() []byte {
	if r.Remaining() <= 0 {
		return nil
	}
	return r.lb.data[r.ReadOffset():r.end]
}

func (r *LargeBufferReader) ReadU8() (uint8, error) {
	b, err := r.ReadN(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *LargeBufferReader) ReadU16LE() (uint16, error) {
	b, err := r.ReadN(2)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint16(b), nil
}

func (r *LargeBufferReader) ReadU32LE() (uint32, error) {
	b, err := r.ReadN(4)
	if err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b), nil
}

func (r *LargeBufferReader) ReadU32BE() (uint32, error) {
	b, err := r.ReadN(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}
