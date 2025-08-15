package httpcap

import (
	"bytes"
	"strings"
)

var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

type Guess struct {
	Proto  string // "http1" | "http2" | ""
	Method string
	Path   string
}

func Classify(prefix []byte) Guess {
	g := Guess{}
	if bytes.HasPrefix(prefix, http2Preface) {
		g.Proto = "http2"
		return g
	}
	if i := bytes.IndexByte(prefix, '\n'); i > 0 {
		line := strings.Trim(string(prefix[:i]), "\r\n")
		f := strings.Fields(line)
		if len(f) >= 3 && strings.HasPrefix(strings.ToUpper(f[2]), "HTTP/1.") {
			g.Proto = "http1"
			g.Method = f[0]
			g.Path = f[1]
			return g
		}
	}
	return g
}
