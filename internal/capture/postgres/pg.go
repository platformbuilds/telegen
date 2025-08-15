package postgres

import "bytes"

// TryParseSimpleQuery recognizes PostgreSQL 'Q' Simple Query messages to extract SQL.
func TryParseSimpleQuery(prefix []byte) (ok bool, sql string) {
	if len(prefix) < 6 || prefix[0] != 'Q' {
		return false, ""
	}
	payload := prefix[5:]
	i := bytes.IndexByte(payload, 0x00)
	if i <= 0 {
		return false, ""
	}
	return true, string(payload[:i])
}
