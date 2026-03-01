// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package flow // import "github.com/mirastacklabs-ai/telegen/internal/flow"

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/golang-lru/v2/expirable"
	"golang.org/x/sync/singleflight"

	ebpf "github.com/mirastacklabs-ai/telegen/internal/netollyebpf"
	"github.com/mirastacklabs-ai/telegen/internal/rdns/ebpf/xdp"
	"github.com/mirastacklabs-ai/telegen/internal/rdns/store"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/swarm"
)

const (
	ReverseDNSNone        = "none"
	ReverseDNSLocalLookup = "local"
	ReverseDNSEBPF        = "ebpf"
)

func rdlog() *slog.Logger {
	return slog.With("component", "flow.ReverseDNS")
}

var netLookupAddr = net.LookupAddr

// ReverseDNS is currently experimental. It is kept disabled by default and will be hidden
// from the documentation. This means that it does not impact in the overall Beyla performance.
type ReverseDNS struct {
	// Type of ReverseDNS. Values are "none" (default), "local" and "ebpf"
	Type string `yaml:"type" env:"OTEL_EBPF_NETWORK_REVERSE_DNS_TYPE" validate:"oneof=none local ebpf"`

	// CacheLen only applies to the "local" and "ebpf" ReverseDNS type. It
	// specifies the max size of the LRU cache that is checked before
	// performing the name lookup. Default: 256
	CacheLen int `yaml:"cache_len" env:"OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_LEN" validate:"gte=0"`

	// CacheTTL only applies to the "local" and "ebpf" ReverseDNS type. It
	// specifies the time-to-live of a cached IP->hostname entry. After the
	// cached entry becomes older than this time, the IP->hostname entry will be looked
	// up again.
	CacheTTL time.Duration `yaml:"cache_expiry" env:"OTEL_EBPF_NETWORK_REVERSE_DNS_CACHE_TTL" validate:"gte=0"`
}

func (r ReverseDNS) Enabled() bool {
	rdType := strings.ToLower(r.Type)
	return rdType == ReverseDNSLocalLookup || rdType == ReverseDNSEBPF
}

func ReverseDNSProvider(cfg *ReverseDNS, input, output *msg.Queue[[]*ebpf.Record]) swarm.InstanceFunc {
	return func(ctx context.Context) (swarm.RunFunc, error) {
		if !cfg.Enabled() {
			return swarm.Bypass(input, output)
		}

		if err := checkEBPFReverseDNS(ctx, cfg); err != nil {
			return nil, err
		}
		// Use jittered cache with singleflight to prevent cache stampedes
		// Jitter is 20% of TTL to spread out expirations
		jitterRange := cfg.CacheTTL / 5
		resolver := &dnsResolver{
			cache:       expirable.NewLRU[ebpf.IPAddr, cachedEntry](cfg.CacheLen, nil, cfg.CacheTTL+jitterRange),
			baseTTL:     cfg.CacheTTL,
			jitterRange: jitterRange,
			log:         rdlog(),
		}

		log := rdlog()
		in := input.Subscribe(msg.SubscriberName("flow.ReverseDNS"))
		return func(_ context.Context) {
			defer output.Close()
			log.Debug("starting reverse DNS node")
			for flows := range in {
				for _, flow := range flows {
					if flow.Attrs.SrcName == "" {
						flow.Attrs.SrcName = resolver.getName(flow.Id.SrcIp.In6U.U6Addr8)
					}
					if flow.Attrs.DstName == "" {
						flow.Attrs.DstName = resolver.getName(flow.Id.DstIp.In6U.U6Addr8)
					}
				}
				output.Send(flows)
			}
		}, nil
	}
}

// changes reverse DNS method according to the provided configuration
func checkEBPFReverseDNS(ctx context.Context, cfg *ReverseDNS) error {
	if cfg.Type == ReverseDNSEBPF {
		// overriding netLookupAddr by an eBPF-based alternative
		ipToHosts, err := store.NewInMemory(cfg.CacheLen)
		if err != nil {
			return fmt.Errorf("initializing eBPF-based reverse DNS cache: %w", err)
		}
		if err := xdp.StartDNSPacketInspector(ctx, ipToHosts); err != nil {
			return fmt.Errorf("starting eBPF-based reverse DNS: %w", err)
		}
		netLookupAddr = ipToHosts.GetHostnames
	}
	return nil
}

// cachedEntry holds a hostname with its jittered expiration time
type cachedEntry struct {
	hostname  string
	expiresAt time.Time
}

// dnsResolver provides cache stampede protection using singleflight
// and jittered expiration times to spread cache invalidations
type dnsResolver struct {
	cache       *expirable.LRU[ebpf.IPAddr, cachedEntry]
	sf          singleflight.Group
	baseTTL     time.Duration
	jitterRange time.Duration
	log         *slog.Logger
	mu          sync.Mutex
	rng         *rand.Rand
}

func (r *dnsResolver) getName(ip ebpf.IPAddr) string {
	// Check cache first
	if entry, ok := r.cache.Get(ip); ok {
		// Check if entry is still valid (jittered expiration)
		if time.Now().Before(entry.expiresAt) {
			return entry.hostname
		}
		// Entry expired - remove it so singleflight can refresh
		r.cache.Remove(ip)
	}

	ipStr := ip.IP().String()

	// Use singleflight to deduplicate concurrent lookups for the same IP
	result, _, _ := r.sf.Do(ipStr, func() (interface{}, error) {
		// Double-check cache in case another goroutine just populated it
		if entry, ok := r.cache.Get(ip); ok && time.Now().Before(entry.expiresAt) {
			return entry.hostname, nil
		}

		names, err := netLookupAddr(ipStr)
		if err != nil {
			r.log.Debug("error trying to lookup by IP address", "ip", ipStr, "error", err)
			return "", err
		}
		if len(names) == 0 {
			return "", nil
		}

		hostname := names[0]
		// Add jitter to TTL to prevent synchronized expirations
		jitter := r.randomJitter()
		entry := cachedEntry{
			hostname:  hostname,
			expiresAt: time.Now().Add(r.baseTTL + jitter),
		}
		r.cache.Add(ip, entry)
		return hostname, nil
	})

	if result == nil {
		return ""
	}
	return result.(string)
}

// randomJitter returns a random duration between 0 and jitterRange
func (r *dnsResolver) randomJitter() time.Duration {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.rng == nil {
		r.rng = rand.New(rand.NewSource(time.Now().UnixNano()))
	}
	return time.Duration(r.rng.Int63n(int64(r.jitterRange)))
}
