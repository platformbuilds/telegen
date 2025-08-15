package queue

import (
	"log"
	"sync"
	"time"
)

type DropReason string

const (
	ReasonFull   DropReason = "queue_full"
	ReasonMaxAge DropReason = "max_age"
)

type Item[T any] struct {
	V       T
	Enqueue time.Time
}

type Ring[T any] struct {
	mu       sync.Mutex
	buf      []Item[T]
	head, sz int
	cap      int
	lastDrop time.Time
	dropped  uint64
	onDrop   func(n uint64, reason DropReason)
}

func NewRing[T any](cap int, onDrop func(n uint64, reason DropReason)) *Ring[T] {
	if cap < 1 {
		cap = 1
	}
	return &Ring[T]{buf: make([]Item[T], cap), cap: cap, onDrop: onDrop}
}

func (q *Ring[T]) Len() int { q.mu.Lock(); defer q.mu.Unlock(); return q.sz }

func (q *Ring[T]) Push(x T) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.sz == q.cap {
		q.head = (q.head + 1) % q.cap
		q.dropped++
		q.coalesceLog(ReasonFull)
	} else {
		q.sz++
	}
	tail := (q.head + q.sz - 1) % q.cap
	q.buf[tail] = Item[T]{V: x, Enqueue: time.Now()}
}

func (q *Ring[T]) PopBatch(maxN int, maxWait time.Duration) []Item[T] {
	deadline := time.Now().Add(maxWait)
	for {
		q.mu.Lock()
		if q.sz > 0 {
			n := maxN
			if n > q.sz {
				n = q.sz
			}
			out := make([]Item[T], n)
			for i := 0; i < n; i++ {
				out[i] = q.buf[(q.head+i)%q.cap]
			}
			q.head = (q.head + n) % q.cap
			q.sz -= n
			q.mu.Unlock()
			return out
		}
		q.mu.Unlock()
		if time.Now().After(deadline) {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (q *Ring[T]) DropExpired(maxAge time.Duration) (dropped int) {
	if maxAge <= 0 {
		return 0
	}
	now := time.Now()
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.sz > 0 {
		it := q.buf[q.head]
		if now.Sub(it.Enqueue) <= maxAge {
			break
		}
		q.head = (q.head + 1) % q.cap
		q.sz--
		dropped++
	}
	if dropped > 0 {
		q.dropped += uint64(dropped)
		q.coalesceLog(ReasonMaxAge)
	}
	return
}

func (q *Ring[T]) coalesceLog(reason DropReason) {
	if time.Since(q.lastDrop) > 10*time.Second {
		log.Printf("queue: dropping oldest telemetry reason=%s total_dropped=%d", reason, q.dropped)
		q.lastDrop = time.Now()
		if q.onDrop != nil {
			q.onDrop(q.dropped, reason)
		}
	}
}
