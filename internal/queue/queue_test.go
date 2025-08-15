package queue

import (
    "testing"
    "time"
)

func TestRingDropOldestOnFull(t *testing.T){
    q := NewRing[int](2, nil)
    q.Push(1); q.Push(2); q.Push(3)
    if q.Len() != 2 { t.Fatalf("len=%d", q.Len()) }
    batch := q.PopBatch(10, time.Millisecond)
    if len(batch) != 2 { t.Fatalf("batch=%d", len(batch)) }
    if batch[0].V != 2 || batch[1].V != 3 { t.Fatalf("order wrong: %+v", batch) }
}

func TestRingDropExpired(t *testing.T){
    q := NewRing[int](3, nil)
    q.Push(1); time.Sleep(5*time.Millisecond)
    q.Push(2); time.Sleep(5*time.Millisecond)
    dropped := q.DropExpired(7*time.Millisecond)
    if dropped == 0 { t.Fatalf("expected drops") }
    if q.Len() == 0 { t.Fatalf("should keep newer") }
}
