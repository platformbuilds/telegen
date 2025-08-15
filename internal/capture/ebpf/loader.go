// internal/capture/ebpf/loader.go
package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"

	"github.com/cilium/ebpf/ringbuf"
)

// Narrow interface makes it easy to fake in tests.
type recordReader interface {
	Read() (ringbuf.Record, error)
	Close() error
}

// Adjust this to your real event struct used by the BPF program.
type tcpEvent struct {
	PID  uint32
	Port uint16
}

type Loader struct {
	rdr    recordReader  // real: *ringbuf.Reader
	events chan tcpEvent // delivered events
}

func (l *Loader) runRingbuf() error {
	rdr := l.rdr
	defer rdr.Close()

	for {
		rec, err := rdr.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil // closed: exit cleanly
			}
			// transient read error — keep looping
			continue
		}

		// Copy: rec.RawSample is reused by the reader.
		payload := append([]byte(nil), rec.RawSample...)

		var ev tcpEvent
		if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, &ev); err != nil {
			// malformed sample — skip
			continue
		}

		select {
		case l.events <- ev:
		default:
			// queue full — drop or block (your policy)
		}
	}
}
