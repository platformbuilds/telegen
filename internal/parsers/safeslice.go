package parsers

// Slice safely returns b[lo:hi]. The second return value is false when bounds are invalid.
func Slice(b []byte, lo, hi int) ([]byte, bool) {
	if lo < 0 || hi < 0 || lo > hi || hi > len(b) {
		return nil, false
	}
	return b[lo:hi], true
}

// Prefix safely returns b[:n]. The second return value is false when bounds are invalid.
func Prefix(b []byte, n int) ([]byte, bool) {
	if n < 0 || n > len(b) {
		return nil, false
	}
	return b[:n], true
}
