package httpcap

import "testing"

func TestClassifyHTTP1(t *testing.T){
    g := Classify([]byte("GET /hello HTTP/1.1\r\nHost: x\r\n"))
    if g.Proto != "http1" || g.Method != "GET" || g.Path != "/hello" {
        t.Fatalf("bad guess: %+v", g)
    }
}
