// Package queue provides persistent queueing with write-ahead logging.
package queue

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// PersistentQueueConfig configures the persistent queue.
type PersistentQueueConfig struct {
	// DataDir is the directory for queue data files.
	DataDir string `yaml:"data_dir" json:"data_dir"`

	// MaxSizeBytes is the maximum total size in bytes.
	// Default: 500MB
	MaxSizeBytes int64 `yaml:"max_size_bytes" json:"max_size_bytes"`

	// MaxItemCount is the maximum number of items.
	// Default: 100000
	MaxItemCount int `yaml:"max_item_count" json:"max_item_count"`

	// SegmentSizeBytes is the size of each WAL segment file.
	// Default: 10MB
	SegmentSizeBytes int64 `yaml:"segment_size_bytes" json:"segment_size_bytes"`

	// SyncOnWrite forces fsync on every write.
	// Default: false (buffered writes)
	SyncOnWrite bool `yaml:"sync_on_write" json:"sync_on_write"`

	// FlushInterval is how often to flush pending writes.
	// Default: 1s
	FlushInterval time.Duration `yaml:"flush_interval" json:"flush_interval"`

	// OnDrop is called when items are dropped.
	OnDrop func(count int, reason DropReason)
}

// DefaultPersistentQueueConfig returns default configuration.
func DefaultPersistentQueueConfig() PersistentQueueConfig {
	return PersistentQueueConfig{
		DataDir:          "/var/lib/telegen/queue",
		MaxSizeBytes:     500 * 1024 * 1024, // 500MB
		MaxItemCount:     100000,
		SegmentSizeBytes: 10 * 1024 * 1024, // 10MB
		SyncOnWrite:      false,
		FlushInterval:    time.Second,
	}
}

// QueuedItem represents an item in the persistent queue.
type QueuedItem struct {
	ID         uint64    `json:"id"`
	SignalType string    `json:"signal_type"`
	Data       []byte    `json:"data"`
	EnqueuedAt time.Time `json:"enqueued_at"`
}

// PersistentQueue is a disk-backed queue with WAL for durability.
type PersistentQueue struct {
	config PersistentQueueConfig

	mu           sync.Mutex
	segments     []*segment
	readSegment  int
	readOffset   int64
	writeSegment int
	nextID       atomic.Uint64
	itemCount    atomic.Int64
	totalBytes   atomic.Int64

	// Stats
	totalPushed  atomic.Int64
	totalPopped  atomic.Int64
	totalDropped atomic.Int64

	flushTicker *time.Ticker
	closeCh     chan struct{}
	closed      bool
}

// segment represents a WAL segment file.
type segment struct {
	path      string
	file      *os.File
	size      int64
	startID   uint64
	endID     uint64
	itemCount int
	readOnly  bool
}

// NewPersistentQueue creates a new persistent queue.
func NewPersistentQueue(config PersistentQueueConfig) (*PersistentQueue, error) {
	if config.DataDir == "" {
		config.DataDir = DefaultPersistentQueueConfig().DataDir
	}
	if config.MaxSizeBytes == 0 {
		config.MaxSizeBytes = DefaultPersistentQueueConfig().MaxSizeBytes
	}
	if config.MaxItemCount == 0 {
		config.MaxItemCount = DefaultPersistentQueueConfig().MaxItemCount
	}
	if config.SegmentSizeBytes == 0 {
		config.SegmentSizeBytes = DefaultPersistentQueueConfig().SegmentSizeBytes
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = DefaultPersistentQueueConfig().FlushInterval
	}

	// Create data directory.
	if err := os.MkdirAll(config.DataDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	pq := &PersistentQueue{
		config:  config,
		closeCh: make(chan struct{}),
	}

	// Load existing segments or create new one.
	if err := pq.loadSegments(); err != nil {
		return nil, fmt.Errorf("failed to load segments: %w", err)
	}

	// Start background flusher.
	pq.flushTicker = time.NewTicker(config.FlushInterval)
	go pq.flushLoop()

	return pq, nil
}

// loadSegments loads existing WAL segments from disk.
func (pq *PersistentQueue) loadSegments() error {
	entries, err := os.ReadDir(pq.config.DataDir)
	if err != nil {
		return err
	}

	var segmentFiles []string
	for _, entry := range entries {
		if !entry.IsDir() && filepath.Ext(entry.Name()) == ".wal" {
			segmentFiles = append(segmentFiles, filepath.Join(pq.config.DataDir, entry.Name()))
		}
	}

	if len(segmentFiles) == 0 {
		// Create initial segment.
		return pq.createNewSegment()
	}

	// Load existing segments.
	for _, path := range segmentFiles {
		seg, err := pq.loadSegment(path)
		if err != nil {
			// Log and skip corrupted segments.
			continue
		}
		pq.segments = append(pq.segments, seg)
		pq.itemCount.Add(int64(seg.itemCount))
		pq.totalBytes.Add(seg.size)
	}

	if len(pq.segments) == 0 {
		return pq.createNewSegment()
	}

	// Mark all but last segment as read-only.
	for i := 0; i < len(pq.segments)-1; i++ {
		pq.segments[i].readOnly = true
	}
	pq.writeSegment = len(pq.segments) - 1

	return nil
}

// loadSegment loads a segment from disk.
func (pq *PersistentQueue) loadSegment(path string) (*segment, error) {
	file, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}

	info, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}

	seg := &segment{
		path: path,
		file: file,
		size: info.Size(),
	}

	// Count items in segment.
	itemCount, startID, endID, err := pq.countItems(file)
	if err != nil {
		file.Close()
		return nil, err
	}

	seg.itemCount = itemCount
	seg.startID = startID
	seg.endID = endID
	if endID > 0 {
		pq.nextID.Store(endID + 1)
	}

	return seg, nil
}

// countItems counts items in a segment file.
func (pq *PersistentQueue) countItems(file *os.File) (count int, startID, endID uint64, err error) {
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		return
	}

	for {
		var length uint32
		if err = binary.Read(file, binary.LittleEndian, &length); err != nil {
			if err == io.EOF {
				err = nil
				break
			}
			return
		}

		data := make([]byte, length)
		if _, err = io.ReadFull(file, data); err != nil {
			return
		}

		var item QueuedItem
		if err = json.Unmarshal(data, &item); err != nil {
			continue // Skip corrupted items.
		}

		if count == 0 {
			startID = item.ID
		}
		endID = item.ID
		count++
	}

	return
}

// createNewSegment creates a new WAL segment.
func (pq *PersistentQueue) createNewSegment() error {
	segmentID := len(pq.segments)
	path := filepath.Join(pq.config.DataDir, fmt.Sprintf("segment-%06d.wal", segmentID))

	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_APPEND, 0644)
	if err != nil {
		return err
	}

	seg := &segment{
		path:    path,
		file:    file,
		startID: pq.nextID.Load(),
	}

	pq.segments = append(pq.segments, seg)
	pq.writeSegment = len(pq.segments) - 1

	return nil
}

// Push adds an item to the queue.
func (pq *PersistentQueue) Push(signalType string, data []byte) error {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if pq.closed {
		return fmt.Errorf("queue is closed")
	}

	// Check limits.
	if pq.itemCount.Load() >= int64(pq.config.MaxItemCount) {
		pq.dropOldest(1)
	}

	// Check size limit.
	itemSize := int64(len(data) + 100) // Overhead for metadata.
	for pq.totalBytes.Load()+itemSize > pq.config.MaxSizeBytes && pq.itemCount.Load() > 0 {
		pq.dropOldest(1)
	}

	// Create item.
	item := QueuedItem{
		ID:         pq.nextID.Add(1) - 1,
		SignalType: signalType,
		Data:       data,
		EnqueuedAt: time.Now(),
	}

	// Serialize.
	itemData, err := json.Marshal(item)
	if err != nil {
		return err
	}

	// Check if we need a new segment.
	currentSeg := pq.segments[pq.writeSegment]
	if currentSeg.size >= pq.config.SegmentSizeBytes {
		currentSeg.readOnly = true
		if err := pq.createNewSegment(); err != nil {
			return err
		}
		currentSeg = pq.segments[pq.writeSegment]
	}

	// Write length-prefixed item.
	length := uint32(len(itemData))
	if err := binary.Write(currentSeg.file, binary.LittleEndian, length); err != nil {
		return err
	}
	n, err := currentSeg.file.Write(itemData)
	if err != nil {
		return err
	}

	currentSeg.size += int64(4 + n)
	currentSeg.itemCount++
	currentSeg.endID = item.ID

	pq.itemCount.Add(1)
	pq.totalBytes.Add(int64(4 + n))
	pq.totalPushed.Add(1)

	if pq.config.SyncOnWrite {
		return currentSeg.file.Sync()
	}

	return nil
}

// Pop removes and returns the oldest item from the queue.
func (pq *PersistentQueue) Pop(ctx context.Context) (*QueuedItem, error) {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if pq.closed {
		return nil, fmt.Errorf("queue is closed")
	}

	for pq.readSegment < len(pq.segments) {
		seg := pq.segments[pq.readSegment]

		// Seek to read position.
		if _, err := seg.file.Seek(pq.readOffset, io.SeekStart); err != nil {
			return nil, err
		}

		// Read length.
		var length uint32
		if err := binary.Read(seg.file, binary.LittleEndian, &length); err != nil {
			if err == io.EOF {
				// Move to next segment.
				if pq.readSegment < pq.writeSegment {
					// Can delete fully read segment.
					pq.deleteSegment(pq.readSegment)
				} else {
					pq.readSegment++
				}
				pq.readOffset = 0
				continue
			}
			return nil, err
		}

		// Read data.
		data := make([]byte, length)
		if _, err := io.ReadFull(seg.file, data); err != nil {
			return nil, err
		}

		// Update read position.
		pq.readOffset += int64(4 + len(data))
		pq.itemCount.Add(-1)
		pq.totalBytes.Add(-int64(4 + len(data)))
		pq.totalPopped.Add(1)

		// Unmarshal item.
		var item QueuedItem
		if err := json.Unmarshal(data, &item); err != nil {
			// Skip corrupted items.
			continue
		}

		return &item, nil
	}

	return nil, nil // Queue is empty.
}

// PopBatch removes and returns up to n items from the queue.
func (pq *PersistentQueue) PopBatch(ctx context.Context, n int) ([]*QueuedItem, error) {
	items := make([]*QueuedItem, 0, n)

	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			return items, ctx.Err()
		default:
		}

		item, err := pq.Pop(ctx)
		if err != nil {
			return items, err
		}
		if item == nil {
			break // Queue is empty.
		}
		items = append(items, item)
	}

	return items, nil
}

// dropOldest drops the oldest n items.
func (pq *PersistentQueue) dropOldest(n int) {
	dropped := 0
	for dropped < n && pq.readSegment < len(pq.segments) {
		seg := pq.segments[pq.readSegment]

		// Seek to read position.
		seg.file.Seek(pq.readOffset, io.SeekStart)

		// Read and discard.
		var length uint32
		if err := binary.Read(seg.file, binary.LittleEndian, &length); err != nil {
			if err == io.EOF {
				if pq.readSegment < pq.writeSegment {
					pq.deleteSegment(pq.readSegment)
				} else {
					pq.readSegment++
				}
				pq.readOffset = 0
				continue
			}
			break
		}

		// Skip data.
		pq.readOffset += int64(4 + int(length))
		pq.itemCount.Add(-1)
		pq.totalBytes.Add(-int64(4 + int(length)))
		dropped++
	}

	pq.totalDropped.Add(int64(dropped))
	if pq.config.OnDrop != nil && dropped > 0 {
		pq.config.OnDrop(dropped, ReasonFull)
	}
}

// deleteSegment removes a fully-read segment.
func (pq *PersistentQueue) deleteSegment(idx int) {
	if idx >= len(pq.segments) {
		return
	}

	seg := pq.segments[idx]
	seg.file.Close()
	os.Remove(seg.path)

	// Remove from slice.
	pq.segments = append(pq.segments[:idx], pq.segments[idx+1:]...)

	// Adjust indices.
	if pq.writeSegment > idx {
		pq.writeSegment--
	}
	if pq.readSegment > idx {
		pq.readSegment--
	}
}

// flushLoop periodically flushes data to disk.
func (pq *PersistentQueue) flushLoop() {
	for {
		select {
		case <-pq.flushTicker.C:
			pq.Flush()
		case <-pq.closeCh:
			return
		}
	}
}

// Flush flushes pending writes to disk.
func (pq *PersistentQueue) Flush() error {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if len(pq.segments) == 0 {
		return nil
	}

	seg := pq.segments[pq.writeSegment]
	if seg.file != nil {
		return seg.file.Sync()
	}
	return nil
}

// Len returns the number of items in the queue.
func (pq *PersistentQueue) Len() int {
	return int(pq.itemCount.Load())
}

// Size returns the total size in bytes.
func (pq *PersistentQueue) Size() int64 {
	return pq.totalBytes.Load()
}

// Stats returns queue statistics.
func (pq *PersistentQueue) Stats() PersistentQueueStats {
	return PersistentQueueStats{
		ItemCount:    int(pq.itemCount.Load()),
		TotalBytes:   pq.totalBytes.Load(),
		TotalPushed:  pq.totalPushed.Load(),
		TotalPopped:  pq.totalPopped.Load(),
		TotalDropped: pq.totalDropped.Load(),
		SegmentCount: len(pq.segments),
	}
}

// PersistentQueueStats holds queue statistics.
type PersistentQueueStats struct {
	ItemCount    int
	TotalBytes   int64
	TotalPushed  int64
	TotalPopped  int64
	TotalDropped int64
	SegmentCount int
}

// Close closes the queue.
func (pq *PersistentQueue) Close() error {
	pq.mu.Lock()
	defer pq.mu.Unlock()

	if pq.closed {
		return nil
	}

	pq.closed = true
	close(pq.closeCh)
	pq.flushTicker.Stop()

	var errs []error
	for _, seg := range pq.segments {
		if seg.file != nil {
			if err := seg.file.Sync(); err != nil {
				errs = append(errs, err)
			}
			if err := seg.file.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("close errors: %v", errs)
	}
	return nil
}
