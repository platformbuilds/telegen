// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package shardedqueue // import "github.com/mirastacklabs-ai/telegen/internal/shardedqueue"

import (
	"context"
	"errors"
	"hash/fnv"
	"sync"
	"sync/atomic"
)

var ErrQueueClosed = errors.New("queue closed")

type ShardedQueue[T any] struct {
	queues []chan T
	hash   func(T) string
	done   atomic.Bool
	mu     sync.RWMutex
	wg     sync.WaitGroup
}

// NewShardedQueue creates a sharded, bounded worker queue.
//
// nWorkers: number of shards
// qLen:     shard channel length
// hash:     sharding function
// worker:   processing function
func NewShardedQueue[T any](
	nWorkers int,
	qLen int,
	hash func(T) string,
	worker func(workerID int, ch <-chan T),
) *ShardedQueue[T] {
	if nWorkers <= 0 {
		nWorkers = 1
	}
	q := &ShardedQueue[T]{
		queues: make([]chan T, nWorkers),
		hash:   hash,
	}

	for i := range nWorkers {
		ch := make(chan T, qLen)
		q.queues[i] = ch
		q.wg.Add(1)
		go func(workerID int, workerCh <-chan T) {
			defer q.wg.Done()
			worker(workerID, workerCh)
		}(i, ch)
	}

	return q
}

// Enqueue adds an item to the appropriate shard.
// Blocks if the shard queue is full.
func (q *ShardedQueue[T]) Enqueue(ctx context.Context, item T) error {
	if q.done.Load() {
		return ErrQueueClosed
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	if q.done.Load() {
		return ErrQueueClosed
	}

	h := fnv.New32a()
	h.Write([]byte(q.hash(item)))
	idx := int(h.Sum32() % uint32(len(q.queues)))

	select {
	case <-ctx.Done():
		return ctx.Err()
	case q.queues[idx] <- item:
		return nil
	}
}

func (q *ShardedQueue[T]) Close() {
	if !q.done.CompareAndSwap(false, true) {
		return
	}
	q.mu.Lock()
	for _, ch := range q.queues {
		close(ch)
	}
	q.mu.Unlock()
	q.wg.Wait()
}
