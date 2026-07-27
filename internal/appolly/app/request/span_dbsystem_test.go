// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package request

import (
	"testing"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
	telegenSemconv "github.com/mirastacklabs-ai/telegen/internal/semconv"
	attr "github.com/mirastacklabs-ai/telegen/pkg/export/attributes/names"
)

func TestSpan_RedisDBSystemName(t *testing.T) {
	tests := []struct {
		name string
		span *Span
		want string
	}{
		{
			name: "plain redis",
			span: &Span{
				Type: EventTypeRedisServer,
				Service: svc.Attrs{
					UID: svc.UID{Name: "redis", Instance: "upi-sim.redis-0.redis"},
				},
			},
			want: telegenSemconv.DBSystemRedis,
		},
		{
			name: "keydb container",
			span: &Span{
				Type: EventTypeRedisClient,
				Service: svc.Attrs{
					UID:      svc.UID{Name: "keydb", Instance: "upi-sim.keydb-0.keydb"},
					Metadata: map[attr.Name]string{attr.K8sContainerName: "keydb"},
				},
			},
			want: telegenSemconv.DBSystemKeyDB,
		},
		{
			name: "valkey container",
			span: &Span{
				Type: EventTypeRedisServer,
				Service: svc.Attrs{
					UID:      svc.UID{Name: "valkey", Instance: "upi-sim.valkey-0.valkey"},
					Metadata: map[attr.Name]string{attr.K8sContainerName: "valkey"},
				},
			},
			want: telegenSemconv.DBSystemValkey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.span.RedisDBSystemName().Value.AsString()
			if got != tt.want {
				t.Fatalf("RedisDBSystemName() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestSpan_DBSystemName_MySQLFamily(t *testing.T) {
	tests := []struct {
		name string
		span *Span
		want string
	}{
		{
			name: "mysql",
			span: &Span{
				Type:    EventTypeSQLClient,
				SubType: int(DBMySQL),
				Service: svc.Attrs{
					UID: svc.UID{Name: "mysql", Instance: "upi-sim.mysql-0.mysqld"},
				},
			},
			want: telegenSemconv.DBSystemMySQL,
		},
		{
			name: "mariadb",
			span: &Span{
				Type:    EventTypeSQLServer,
				SubType: int(DBMySQL),
				Service: svc.Attrs{
					UID:      svc.UID{Name: "mariadb", Instance: "upi-sim.mariadb-0.mariadbd"},
					Metadata: map[attr.Name]string{attr.K8sContainerName: "mariadbd"},
				},
			},
			want: telegenSemconv.DBSystemMariaDB,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.span.DBSystemName().Value.AsString()
			if got != tt.want {
				t.Fatalf("DBSystemName() = %q, want %q", got, tt.want)
			}
		})
	}
}
