package queue

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestPersistentQueue_Create(t *testing.T) {
	dir := t.TempDir()
	config := PersistentQueueConfig{
		DataDir:      dir,
		MaxSizeBytes: 1024 * 1024,
		MaxItemCount: 1000,
	}

	pq, err := NewPersistentQueue(config)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer pq.Close()

	if pq.Len() != 0 {
		t.Errorf("expected empty queue, got %d items", pq.Len())
	}
}

func TestPersistentQueue_PushPop(t *testing.T) {
	dir := t.TempDir()
	config := PersistentQueueConfig{
		DataDir:      dir,
		MaxSizeBytes: 1024 * 1024,
		MaxItemCount: 1000,
	}

	pq, err := NewPersistentQueue(config)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer pq.Close()

	// Push items.
	for i := 0; i < 10; i++ {
		data := []byte("test data")
		if err := pq.Push("traces", data); err != nil {
			t.Fatalf("push failed: %v", err)
		}
	}

	if pq.Len() != 10 {
		t.Errorf("expected 10 items, got %d", pq.Len())
	}

	// Pop items.
	ctx := context.Background()
	for i := 0; i < 10; i++ {
		item, err := pq.Pop(ctx)
		if err != nil {
			t.Fatalf("pop failed: %v", err)
		}
		if item == nil {
			t.Fatal("expected item, got nil")
		}
		if item.SignalType != "traces" {
			t.Errorf("expected signal type 'traces', got %s", item.SignalType)
		}
		if string(item.Data) != "test data" {
			t.Errorf("expected 'test data', got %s", string(item.Data))
		}
	}

	if pq.Len() != 0 {
		t.Errorf("expected empty queue, got %d items", pq.Len())
	}

	// Pop from empty queue.
	item, err := pq.Pop(ctx)
	if err != nil {
		t.Fatalf("pop on empty failed: %v", err)
	}
	if item != nil {
		t.Error("expected nil from empty queue")
	}
}

func TestPersistentQueue_PopBatch(t *testing.T) {
	dir := t.TempDir()
	config := PersistentQueueConfig{
		DataDir:      dir,
		MaxSizeBytes: 1024 * 1024,
		MaxItemCount: 1000,
	}

	pq, err := NewPersistentQueue(config)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer pq.Close()

	// Push 15 items.
	for i := 0; i < 15; i++ {
		pq.Push("logs", []byte("log data"))
	}

	ctx := context.Background()

	// Pop batch of 10.
	items, err := pq.PopBatch(ctx, 10)
	if err != nil {
		t.Fatalf("pop batch failed: %v", err)
	}
	if len(items) != 10 {
		t.Errorf("expected 10 items, got %d", len(items))
	}
	if pq.Len() != 5 {
		t.Errorf("expected 5 remaining, got %d", pq.Len())
	}

	// Pop remaining.
	items, err = pq.PopBatch(ctx, 10)
	if err != nil {
		t.Fatalf("pop batch failed: %v", err)
	}
	if len(items) != 5 {
		t.Errorf("expected 5 items, got %d", len(items))
	}
}

func TestPersistentQueue_MaxItemCount(t *testing.T) {
	dir := t.TempDir()
	config := PersistentQueueConfig{
		DataDir:      dir,
		MaxSizeBytes: 1024 * 1024,
		MaxItemCount: 5,
	}

	var dropped int
	config.OnDrop = func(count int, reason DropReason) {
		dropped += count
	}

	pq, err := NewPersistentQueue(config)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer pq.Close()

	// Push more than max.
	for i := 0; i < 10; i++ {
		pq.Push("metrics", []byte("metric data"))
	}

	if pq.Len() > 5 {
		t.Errorf("expected max 5 items, got %d", pq.Len())
	}

	stats := pq.Stats()
	if stats.TotalDropped == 0 {
		t.Error("expected some items to be dropped")
	}
}

func TestPersistentQueue_Persistence(t *testing.T) {
	dir := t.TempDir()
	config := PersistentQueueConfig{
		DataDir:      dir,
		MaxSizeBytes: 1024 * 1024,
		MaxItemCount: 1000,
		SyncOnWrite:  true,
	}

	// Create and populate.
	pq, err := NewPersistentQueue(config)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}

	for i := 0; i < 5; i++ {
		pq.Push("traces", []byte("persistent data"))
	}
	pq.Close()

	// Verify WAL file exists.
	files, _ := os.ReadDir(dir)
	walFound := false
	for _, f := range files {
		if filepath.Ext(f.Name()) == ".wal" {
			walFound = true
			break
		}
	}
	if !walFound {
		t.Error("expected WAL file to exist")
	}

	// Reopen and verify data persisted.
	pq2, err := NewPersistentQueue(config)
	if err != nil {
		t.Fatalf("failed to reopen queue: %v", err)
	}
	defer pq2.Close()

	if pq2.Len() != 5 {
		t.Errorf("expected 5 items after reopen, got %d", pq2.Len())
	}

	ctx := context.Background()
	item, err := pq2.Pop(ctx)
	if err != nil {
		t.Fatalf("pop failed: %v", err)
	}
	if string(item.Data) != "persistent data" {
		t.Errorf("expected 'persistent data', got %s", string(item.Data))
	}
}

func TestPersistentQueue_Segmentation(t *testing.T) {
	dir := t.TempDir()
	config := PersistentQueueConfig{
		DataDir:          dir,
		MaxSizeBytes:     1024 * 1024,
		MaxItemCount:     10000,
		SegmentSizeBytes: 500, // Very small segment size.
	}

	pq, err := NewPersistentQueue(config)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer pq.Close()

	// Push enough data to create multiple segments.
	for i := 0; i < 50; i++ {
		pq.Push("traces", []byte("segment test data that is somewhat long"))
	}

	stats := pq.Stats()
	if stats.SegmentCount < 2 {
		t.Errorf("expected multiple segments, got %d", stats.SegmentCount)
	}
}

func TestPersistentQueue_Stats(t *testing.T) {
	dir := t.TempDir()
	config := PersistentQueueConfig{
		DataDir:      dir,
		MaxSizeBytes: 1024 * 1024,
		MaxItemCount: 1000,
	}

	pq, err := NewPersistentQueue(config)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer pq.Close()

	// Push and pop.
	for i := 0; i < 10; i++ {
		pq.Push("metrics", []byte("stats test"))
	}

	ctx := context.Background()
	for i := 0; i < 3; i++ {
		pq.Pop(ctx)
	}

	stats := pq.Stats()
	if stats.TotalPushed != 10 {
		t.Errorf("expected 10 pushed, got %d", stats.TotalPushed)
	}
	if stats.TotalPopped != 3 {
		t.Errorf("expected 3 popped, got %d", stats.TotalPopped)
	}
	if stats.ItemCount != 7 {
		t.Errorf("expected 7 items, got %d", stats.ItemCount)
	}
}

func TestPersistentQueue_Flush(t *testing.T) {
	dir := t.TempDir()
	config := PersistentQueueConfig{
		DataDir:       dir,
		MaxSizeBytes:  1024 * 1024,
		MaxItemCount:  1000,
		FlushInterval: 50 * time.Millisecond,
	}

	pq, err := NewPersistentQueue(config)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}

	// Push data.
	pq.Push("traces", []byte("flush test"))

	// Manual flush.
	if err := pq.Flush(); err != nil {
		t.Errorf("flush failed: %v", err)
	}

	pq.Close()
}

func TestPersistentQueue_CloseIdempotent(t *testing.T) {
	dir := t.TempDir()
	config := PersistentQueueConfig{
		DataDir:      dir,
		MaxSizeBytes: 1024 * 1024,
		MaxItemCount: 1000,
	}

	pq, err := NewPersistentQueue(config)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}

	// Close multiple times should not panic.
	pq.Close()
	pq.Close()
}

func TestPersistentQueue_OperationsAfterClose(t *testing.T) {
	dir := t.TempDir()
	config := PersistentQueueConfig{
		DataDir:      dir,
		MaxSizeBytes: 1024 * 1024,
		MaxItemCount: 1000,
	}

	pq, err := NewPersistentQueue(config)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	pq.Close()

	// Operations should fail.
	if err := pq.Push("traces", []byte("data")); err == nil {
		t.Error("expected error on push after close")
	}

	ctx := context.Background()
	_, err = pq.Pop(ctx)
	if err == nil {
		t.Error("expected error on pop after close")
	}
}

func TestPersistentQueue_SignalTypes(t *testing.T) {
	dir := t.TempDir()
	config := PersistentQueueConfig{
		DataDir:      dir,
		MaxSizeBytes: 1024 * 1024,
		MaxItemCount: 1000,
	}

	pq, err := NewPersistentQueue(config)
	if err != nil {
		t.Fatalf("failed to create queue: %v", err)
	}
	defer pq.Close()

	// Push different signal types.
	pq.Push("traces", []byte("trace data"))
	pq.Push("logs", []byte("log data"))
	pq.Push("metrics", []byte("metric data"))

	ctx := context.Background()

	// Verify FIFO order and signal types.
	item, _ := pq.Pop(ctx)
	if item.SignalType != "traces" {
		t.Errorf("expected traces, got %s", item.SignalType)
	}

	item, _ = pq.Pop(ctx)
	if item.SignalType != "logs" {
		t.Errorf("expected logs, got %s", item.SignalType)
	}

	item, _ = pq.Pop(ctx)
	if item.SignalType != "metrics" {
		t.Errorf("expected metrics, got %s", item.SignalType)
	}
}
