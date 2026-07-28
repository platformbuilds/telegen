// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package semconv

import (
	"strings"
)

const (
	DBSystemKeyDB  = "keydb"
	DBSystemValkey = "valkey"
)

// ResolveDBSystemFromExecutableHints refines a default db.system value using
// process / service identity hints (executable basename, K8s container name,
// service.instance, etc.). When no hint matches a known product, defaultSystem
// is returned unchanged.
func ResolveDBSystemFromExecutableHints(defaultSystem string, hints ...string) string {
	combined := strings.ToLower(strings.Join(hints, " "))
	if combined == "" {
		return defaultSystem
	}

	switch defaultSystem {
	case DBSystemRedis:
		if strings.Contains(combined, "valkey") {
			return DBSystemValkey
		}
		if strings.Contains(combined, "keydb") {
			return DBSystemKeyDB
		}
		return DBSystemRedis
	case DBSystemMySQL, DBSystemMariaDB:
		if strings.Contains(combined, "mariadb") || strings.Contains(combined, "mariadbd") {
			return DBSystemMariaDB
		}
		if strings.Contains(combined, "mysqld") || strings.Contains(combined, "mysql") {
			return DBSystemMySQL
		}
		return defaultSystem
	case DBSystemPostgreSQL:
		// Defense in depth: if the process/container is explicitly a MariaDB/MySQL server,
		// never emit postgresql. A genuine Postgres process matches none of these tokens and
		// keeps postgresql unchanged.
		if strings.Contains(combined, "mariadb") || strings.Contains(combined, "mariadbd") {
			return DBSystemMariaDB
		}
		if strings.Contains(combined, "mysqld") || strings.Contains(combined, "mysql") {
			return DBSystemMySQL
		}
		return DBSystemPostgreSQL
	default:
		return defaultSystem
	}
}
