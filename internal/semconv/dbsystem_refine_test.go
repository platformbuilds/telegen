// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package semconv

import "testing"

func TestResolveDBSystemFromExecutableHints_RedisFamily(t *testing.T) {
	tests := []struct {
		name          string
		defaultSystem string
		hints         []string
		want          string
	}{
		{name: "empty hints keeps redis", defaultSystem: DBSystemRedis, hints: nil, want: DBSystemRedis},
		{name: "redis-server", defaultSystem: DBSystemRedis, hints: []string{"redis-server"}, want: DBSystemRedis},
		{name: "keydb-server", defaultSystem: DBSystemRedis, hints: []string{"keydb-server"}, want: DBSystemKeyDB},
		{name: "keydb container", defaultSystem: DBSystemRedis, hints: []string{"upi-sim", "keydb-0", "keydb"}, want: DBSystemKeyDB},
		{name: "valkey-server", defaultSystem: DBSystemRedis, hints: []string{"valkey-server"}, want: DBSystemValkey},
		{name: "valkey instance", defaultSystem: DBSystemRedis, hints: []string{"upi-sim.valkey-0.valkey"}, want: DBSystemValkey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveDBSystemFromExecutableHints(tt.defaultSystem, tt.hints...)
			if got != tt.want {
				t.Fatalf("ResolveDBSystemFromExecutableHints() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveDBSystemFromExecutableHints_MySQLFamily(t *testing.T) {
	tests := []struct {
		name          string
		defaultSystem string
		hints         []string
		want          string
	}{
		{name: "mysqld", defaultSystem: DBSystemMySQL, hints: []string{"mysqld"}, want: DBSystemMySQL},
		{name: "mariadbd", defaultSystem: DBSystemMySQL, hints: []string{"mariadbd"}, want: DBSystemMariaDB},
		{name: "libmariadb in path", defaultSystem: DBSystemMySQL, hints: []string{"/usr/lib/libmariadb.so"}, want: DBSystemMariaDB},
		{name: "unknown keeps default", defaultSystem: DBSystemMySQL, hints: []string{"api-gateway"}, want: DBSystemMySQL},
		{name: "mariadb default preserved", defaultSystem: DBSystemMariaDB, hints: []string{"custom"}, want: DBSystemMariaDB},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveDBSystemFromExecutableHints(tt.defaultSystem, tt.hints...)
			if got != tt.want {
				t.Fatalf("ResolveDBSystemFromExecutableHints() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestResolveDBSystemFromExecutableHints_PostgreSQLSafetyNet(t *testing.T) {
	tests := []struct {
		name  string
		hints []string
		want  string
	}{
		{name: "postgres process keeps postgresql", hints: []string{"postgres"}, want: DBSystemPostgreSQL},
		{name: "mariadb process downgrades", hints: []string{"mariadbd"}, want: DBSystemMariaDB},
		{name: "mysql process downgrades", hints: []string{"mysqld"}, want: DBSystemMySQL},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ResolveDBSystemFromExecutableHints(DBSystemPostgreSQL, tt.hints...)
			if got != tt.want {
				t.Fatalf("ResolveDBSystemFromExecutableHints() = %q, want %q", got, tt.want)
			}
		})
	}
}
