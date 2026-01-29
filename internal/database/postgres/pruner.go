// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

// Package postgres provides PostgreSQL-specific database tracing utilities.
package postgres

import (
	"strings"
	"unicode"
)

// Pruner normalizes and prunes sensitive data from PostgreSQL queries.
// It replaces literal values with placeholders to:
// 1. Enable query pattern aggregation
// 2. Protect sensitive data (PII, credentials, etc.)
// 3. Reduce storage/transmission size
type Pruner struct {
	// MaxQueryLength is the maximum length of the output query.
	MaxQueryLength int

	// PreserveFunctionNames keeps function names visible.
	PreserveFunctionNames bool

	// PreserveTableNames keeps table names visible.
	PreserveTableNames bool

	// RedactComments removes SQL comments.
	RedactComments bool
}

// DefaultPruner returns a Pruner with default settings.
func DefaultPruner() *Pruner {
	return &Pruner{
		MaxQueryLength:        2048,
		PreserveFunctionNames: true,
		PreserveTableNames:    true,
		RedactComments:        true,
	}
}

// Prune normalizes a PostgreSQL query by replacing literals with placeholders.
func (p *Pruner) Prune(query string) string {
	if len(query) == 0 {
		return query
	}

	// Pre-allocate result buffer
	result := make([]byte, 0, len(query))
	i := 0
	n := len(query)

	for i < n {
		c := query[i]

		// Handle comments
		if p.RedactComments {
			// Single-line comment: -- ...
			if c == '-' && i+1 < n && query[i+1] == '-' {
				// Skip to end of line
				for i < n && query[i] != '\n' {
					i++
				}
				result = append(result, ' ')
				continue
			}

			// Multi-line comment: /* ... */
			if c == '/' && i+1 < n && query[i+1] == '*' {
				i += 2
				for i+1 < n && !(query[i] == '*' && query[i+1] == '/') {
					i++
				}
				i += 2 // Skip */
				result = append(result, ' ')
				continue
			}
		}

		// Handle string literals: 'string' or E'string' or $$string$$
		if c == '\'' || (c == 'E' && i+1 < n && query[i+1] == '\'') {
			if c == 'E' {
				i++ // Skip E
			}
			i++ // Skip opening quote

			// Find closing quote (handle escaped quotes)
			for i < n {
				if query[i] == '\'' {
					if i+1 < n && query[i+1] == '\'' {
						i += 2 // Escaped quote
						continue
					}
					break
				}
				if query[i] == '\\' && i+1 < n {
					i += 2 // Escape sequence
					continue
				}
				i++
			}
			i++ // Skip closing quote
			result = append(result, '?')
			continue
		}

		// Handle dollar-quoted strings: $$string$$ or $tag$string$tag$
		if c == '$' {
			// Find the tag
			tagEnd := i + 1
			for tagEnd < n && (isIdentChar(query[tagEnd]) || query[tagEnd] == '$') {
				if query[tagEnd] == '$' {
					break
				}
				tagEnd++
			}

			if tagEnd < n && query[tagEnd] == '$' {
				tag := query[i : tagEnd+1]
				i = tagEnd + 1

				// Find closing tag
				for i+len(tag) <= n {
					if query[i:i+len(tag)] == tag {
						i += len(tag)
						break
					}
					i++
				}
				result = append(result, '?')
				continue
			}
		}

		// Handle numeric literals
		if isDigit(c) || (c == '.' && i+1 < n && isDigit(query[i+1])) {
			// Check if this is part of an identifier
			if i > 0 && isIdentChar(query[i-1]) {
				result = append(result, c)
				i++
				continue
			}

			// Parse the number
			start := i
			hasDecimal := c == '.'
			i++

			for i < n {
				c2 := query[i]
				if isDigit(c2) {
					i++
				} else if c2 == '.' && !hasDecimal {
					hasDecimal = true
					i++
				} else if c2 == 'e' || c2 == 'E' {
					// Scientific notation
					i++
					if i < n && (query[i] == '+' || query[i] == '-') {
						i++
					}
				} else {
					break
				}
			}

			// Check if this looks like a valid number
			numStr := query[start:i]
			if isValidNumber(numStr) {
				result = append(result, '?')
			} else {
				result = append(result, numStr...)
			}
			continue
		}

		// Handle binary/hex literals: B'...' or X'...'
		if (c == 'B' || c == 'b' || c == 'X' || c == 'x') && i+1 < n && query[i+1] == '\'' {
			i += 2 // Skip B' or X'
			for i < n && query[i] != '\'' {
				i++
			}
			i++ // Skip closing quote
			result = append(result, '?')
			continue
		}

		// Handle parameter placeholders: $1, $2, etc.
		if c == '$' && i+1 < n && isDigit(query[i+1]) {
			// Keep the placeholder as-is
			result = append(result, c)
			i++
			for i < n && isDigit(query[i]) {
				result = append(result, query[i])
				i++
			}
			continue
		}

		// Handle PostgreSQL type casts: ::type
		if c == ':' && i+1 < n && query[i+1] == ':' {
			result = append(result, ':', ':')
			i += 2
			// Keep the type name
			for i < n && (isIdentChar(query[i]) || query[i] == '.') {
				result = append(result, query[i])
				i++
			}
			continue
		}

		// Handle array literals: ARRAY[...]
		if strings.HasPrefix(strings.ToUpper(query[i:]), "ARRAY[") {
			result = append(result, "ARRAY[?]"...)
			i += 6 // Skip ARRAY[
			brackets := 1
			for i < n && brackets > 0 {
				if query[i] == '[' {
					brackets++
				} else if query[i] == ']' {
					brackets--
				}
				i++
			}
			continue
		}

		// Handle IN lists: IN (val1, val2, ...)
		if strings.HasPrefix(strings.ToUpper(query[i:]), "IN") && i+2 < n {
			// Check for whitespace and opening paren
			j := i + 2
			for j < n && unicode.IsSpace(rune(query[j])) {
				j++
			}
			if j < n && query[j] == '(' {
				result = append(result, "IN (?)"...)
				i = j + 1
				parens := 1
				for i < n && parens > 0 {
					if query[i] == '(' {
						parens++
					} else if query[i] == ')' {
						parens--
					}
					i++
				}
				continue
			}
		}

		// Handle VALUES lists
		if strings.HasPrefix(strings.ToUpper(query[i:]), "VALUES") && i+6 < n {
			j := i + 6
			for j < n && unicode.IsSpace(rune(query[j])) {
				j++
			}
			if j < n && query[j] == '(' {
				result = append(result, "VALUES (?)"...)
				i = j
				// Skip all value tuples
				for i < n && (query[i] == '(' || query[i] == ',' || unicode.IsSpace(rune(query[i]))) {
					if query[i] == '(' {
						parens := 1
						i++
						for i < n && parens > 0 {
							if query[i] == '(' {
								parens++
							} else if query[i] == ')' {
								parens--
							}
							i++
						}
					} else {
						i++
					}
				}
				continue
			}
		}

		// Collapse consecutive whitespace
		if unicode.IsSpace(rune(c)) {
			if len(result) > 0 && result[len(result)-1] != ' ' {
				result = append(result, ' ')
			}
			for i < n && unicode.IsSpace(rune(query[i])) {
				i++
			}
			continue
		}

		// Regular character
		result = append(result, c)
		i++
	}

	// Trim and truncate
	output := strings.TrimSpace(string(result))
	if len(output) > p.MaxQueryLength {
		output = output[:p.MaxQueryLength-3] + "..."
	}

	return output
}

// NormalizeQuery provides a simpler normalization that just replaces literals.
func (p *Pruner) NormalizeQuery(query string) string {
	return p.Prune(query)
}

// ExtractTables extracts table names from a SQL query.
// This is a simplified implementation that handles common cases.
func (p *Pruner) ExtractTables(query string) []string {
	tables := make([]string, 0)
	upper := strings.ToUpper(query)

	// Look for FROM and JOIN clauses
	keywords := []string{"FROM ", "JOIN ", "UPDATE ", "INTO "}

	for _, keyword := range keywords {
		idx := 0
		for {
			pos := strings.Index(upper[idx:], keyword)
			if pos == -1 {
				break
			}
			pos += idx + len(keyword)

			// Skip whitespace
			for pos < len(query) && unicode.IsSpace(rune(query[pos])) {
				pos++
			}

			// Extract table name
			start := pos
			for pos < len(query) && (isIdentChar(query[pos]) || query[pos] == '.') {
				pos++
			}

			if pos > start {
				table := query[start:pos]
				// Skip PostgreSQL schema qualifiers if desired
				if !p.PreserveTableNames {
					table = "?"
				}
				tables = append(tables, table)
			}

			idx = pos
		}
	}

	return tables
}

// Helper functions

func isDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

func isIdentChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}

func isValidNumber(s string) bool {
	if len(s) == 0 {
		return false
	}

	hasDigit := false
	hasDecimal := false

	for i, c := range s {
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c == '.':
			if hasDecimal {
				return false
			}
			hasDecimal = true
		case (c == 'e' || c == 'E') && i > 0:
			// Allow exponent notation
		case (c == '+' || c == '-') && i > 0 && (s[i-1] == 'e' || s[i-1] == 'E'):
			// Allow sign after exponent
		default:
			return false
		}
	}

	return hasDigit
}

// RedactSensitive redacts potentially sensitive fields from queries.
// This includes password fields, credit card patterns, etc.
func RedactSensitive(query string) string {
	// Patterns for sensitive data
	sensitivePatterns := []string{
		"password", "passwd", "pwd", "secret", "token",
		"api_key", "apikey", "auth", "credential",
		"ssn", "social_security", "credit_card", "cc_number",
	}

	lower := strings.ToLower(query)

	for _, pattern := range sensitivePatterns {
		if strings.Contains(lower, pattern) {
			// Find and redact the value associated with this field
			// This is a simplified implementation
			idx := strings.Index(lower, pattern)
			if idx != -1 {
				// Look for = or : after the pattern
				for i := idx + len(pattern); i < len(query) && i < idx+len(pattern)+50; i++ {
					c := query[i]
					if c == '=' || c == ':' {
						// Redact the following value
						start := i + 1
						for start < len(query) && unicode.IsSpace(rune(query[start])) {
							start++
						}
						// Find end of value
						end := start
						if query[start] == '\'' || query[start] == '"' {
							quote := query[start]
							end = start + 1
							for end < len(query) && query[end] != quote {
								end++
							}
							end++ // Include closing quote
						} else {
							for end < len(query) && !unicode.IsSpace(rune(query[end])) && query[end] != ',' && query[end] != ')' {
								end++
							}
						}
						if end > start {
							query = query[:start] + "[REDACTED]" + query[end:]
							lower = strings.ToLower(query)
						}
						break
					}
				}
			}
		}
	}

	return query
}
