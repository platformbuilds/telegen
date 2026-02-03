// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package sharding

import (
	"hash/fnv"
)

// Sharder determines which shard an object belongs to
type Sharder struct {
	shard       int
	totalShards int
}

// NewSharder creates a new Sharder
func NewSharder(shard, totalShards int) *Sharder {
	return &Sharder{
		shard:       shard,
		totalShards: totalShards,
	}
}

// IsMine returns true if the object belongs to this shard
// Uses jump consistent hash for even distribution
func (s *Sharder) IsMine(uid string) bool {
	if s.totalShards <= 1 {
		return true
	}
	return s.shard == JumpConsistentHash(uid, s.totalShards)
}

// JumpConsistentHash implements Google's Jump Consistent Hash algorithm
// https://arxiv.org/abs/1406.2294
func JumpConsistentHash(key string, numBuckets int) int {
	h := fnv.New64a()
	h.Write([]byte(key))
	keyHash := h.Sum64()
	return jumpHash(keyHash, numBuckets)
}

// jumpHash is the core algorithm
func jumpHash(key uint64, numBuckets int) int {
	var b int64 = -1
	var j int64 = 0

	for j < int64(numBuckets) {
		b = j
		key = key*2862933555777941757 + 1
		j = int64(float64(b+1) * (float64(int64(1)<<31) / float64((key>>33)+1)))
	}

	return int(b)
}

// ShardingConfig holds sharding configuration
type ShardingConfig struct {
	// Shard is the current shard index (0-based)
	Shard int
	// TotalShards is the total number of shards
	TotalShards int
}

// Validate validates the sharding configuration
func (c *ShardingConfig) Validate() error {
	if c.TotalShards < 1 {
		c.TotalShards = 1
	}
	if c.Shard < 0 {
		c.Shard = 0
	}
	if c.Shard >= c.TotalShards {
		c.Shard = 0
	}
	return nil
}

// IsEnabled returns true if sharding is enabled
func (c *ShardingConfig) IsEnabled() bool {
	return c.TotalShards > 1
}
