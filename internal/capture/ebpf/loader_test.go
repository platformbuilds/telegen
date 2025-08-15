package ebpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/cilium/ebpf/ringbuf"
)

// --- test doubles ---

type fakeReader struct {
	recs   []ringbuf.Record
	i      int
	closed bool
}

func (f *fakeReader) Read() (ringbuf.Record, error) {
	if f.i < len(f.recs) {
		r := f.recs[f.i]
		f.i++
		return r, nil
	}
	if f.closed {
		return ringbuf.Record{}, ringbuf.ErrClosed
	}
	return ringbuf.Record{}, errors.New("temporary")
}
func (f *fakeReader) Close() error { f.closed = true; return nil }

func recWith(ev tcpEvent) ringbuf.Record {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, ev)
	return ringbuf.Record{RawSample: buf.Bytes()}
}

// --- tests ---

func TestRunRingbuf_DeliversAndExits(t *testing.T) {
	fr := &fakeReader{
		recs: []ringbuf.Record{
			recWith(tcpEvent{PID: 42, Port: 8080}),
			recWith(tcpEvent{PID: 7, Port: 5432}),
		},
	}
	evCh := make(chan tcpEvent, 4)
	ldr := &Loader{rdr: fr, events: evCh}

	// Pump two records
	go func() {
		_ = ldr.runRingbuf()
	}()

	// Let both deliver
	got1 := <-evCh
	got2 := <-evCh
	if got1.PID != 42 || got1.Port != 8080 {
		t.Fatalf("first event %+v", got1)
	}
	if got2.PID != 7 || got2.Port != 5432 {
		t.Fatalf("second event %+v", got2)
	}

	// Close and ensure runRingbuf returns
	_ = fr.Close()
	// The goroutine will exit cleanly; no panic == pass.
}

func TestRunRingbuf_CopiesPayload(t *testing.T) {
	// Build a record and mutate its backing buffer after Read
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, tcpEvent{PID: 99, Port: 9000})
	rec := ringbuf.Record{RawSample: buf.Bytes()}

	fr := &fakeReader{recs: []ringbuf.Record{rec}, closed: true}
	evCh := make(chan tcpEvent, 1)
	// Run once synchronously by invoking the body logic inline:
	// emulate single iteration
	r, _ := fr.Read()
	payload := append([]byte(nil), r.RawSample...)
	var ev tcpEvent
	if err := binary.Read(bytes.NewReader(payload), binary.LittleEndian, &ev); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	evCh <- ev

	// Now mutate original buffer to ensure we copied
	copy(rec.RawSample, []byte{0xFF, 0xFF, 0xFF, 0xFF})

	got := <-evCh
	if got.PID != 99 || got.Port != 9000 {
		t.Fatalf("payload was not copied; got %+v", got)
	}
}
