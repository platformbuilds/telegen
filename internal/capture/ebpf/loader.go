package ebpfcap

import (
    "bytes"
    "context"
    "embed"
    "errors"
    "log"
    "runtime"
    "time"

    "github.com/cilium/ebpf"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
)

//go:embed tcpevents_bpfel.o tcpevents_bpfeb.o
var bpfObjs embed.FS

type Event struct {
    TsNs  uint64
    Dport uint16
    Bytes uint64
    Dir   uint8 // 0=send,1=recv
    PID   uint32
}

type Loader struct{
    events chan Event
    reader *ringbuf.Reader
    links  []link.Link
}

func New() (*Loader, error) { return &Loader{ events: make(chan Event, 4096) }, nil }
func (l *Loader) Events() <-chan Event { return l.events }

func isBigEndian() bool {
    switch runtime.GOARCH {
    case "s390x", "ppc64":
        return true
    default:
        return false
    }
}

func (l *Loader) loadObj() ([]byte, error) {
    name := "tcpevents_bpfel.o"
    if isBigEndian() { name = "tcpevents_bpfeb.o" }
    return bpfObjs.ReadFile(name)
}

func (l *Loader) Run(ctx context.Context) error {
    objBytes, err := l.loadObj()
    if err != nil {
        log.Printf("ebpf: no embedded CO-RE object: %v; falling back to simulator", err)
        return l.simulate(ctx)
    }
    spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objBytes))
    if err != nil { log.Printf("ebpf: parse failed: %v; simulator fallback", err); return l.simulate(ctx) }
    coll, err := ebpf.NewCollection(spec)
    if err != nil { log.Printf("ebpf: load failed: %v; simulator fallback", err); return l.simulate(ctx) }
    defer coll.Close()

    send, err := link.Kprobe("tcp_sendmsg", coll.Programs["k_tcp_sendmsg"], nil)
    if err != nil { log.Printf("ebpf: kprobe send: %v; simulator fallback", err); return l.simulate(ctx) }
    recv, err := link.Kprobe("tcp_cleanup_rbuf", coll.Programs["k_tcp_cleanup_rbuf"], nil)
    if err != nil { _ = send.Close(); log.Printf("ebpf: kprobe recv: %v; simulator fallback", err); return l.simulate(ctx) }
    l.links = []link.Link{ send, recv }
    defer func(){ for _, lk := range l.links { _ = lk.Close() } }()

    rb, ok := coll.Maps["events"]
    if !ok { return errors.New("events ringbuf not found") }
    rdr, err := ringbuf.NewReader(rb)
    if err != nil { log.Printf("ebpf: ringbuf reader: %v; simulator fallback", err); return l.simulate(ctx) }
    l.reader = rdr
    defer rdr.Close()

    for {
        rec, err := rdr.Read()
        if err != nil {
            if errors.Is(err, ringbuf.ErrClosed) { return nil }
            continue
        }
        // expect 24 bytes layout; if not, drop
        b := rec.RawSample
        if len(b) >= 24 {
            e := Event{
                TsNs:  uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
                       uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56,
                Dport: uint16(b[8]) | uint16(b[9])<<8,
                Bytes: uint64(b[10]) | uint64(b[11])<<8 | uint64(b[12])<<16 | uint64(b[13])<<24 |
                       uint64(b[14])<<32 | uint64(b[15])<<40 | uint64(b[16])<<48 | uint64(b[17])<<56,
                Dir:   b[18],
                PID:   uint32(b[20]) | uint32(b[21])<<8 | uint32(b[22])<<16 | uint32(b[23])<<24,
            }
            l.events <- e
        }
        rdr.CloseRecord(rec)
    }
}

func (l *Loader) Close() { if l.reader != nil { _ = l.reader.Close() } }

func (l *Loader) simulate(ctx context.Context) error {
    t := time.NewTicker(2 * time.Second); defer t.Stop()
    for {
        select {
        case <-ctx.Done(): return nil
        case <-t.C:
            now := time.Now().UnixNano()
            l.events <- Event{ TsNs: uint64(now), Dport: 80, Bytes: 200, Dir: 0 }
            l.events <- Event{ TsNs: uint64(now+50_000_000), Dport: 80, Bytes: 1024, Dir: 1 }
        }
    }
}
