package postgres

import "testing"

func TestTryParseSimpleQuery(t *testing.T){
    pkt := append([]byte{'Q',0,0,0,20}, []byte("SELECT 1;")...)
    pkt = append(pkt, 0)
    ok, sql := TryParseSimpleQuery(pkt)
    if !ok { t.Fatalf("expected ok") }
    if sql != "SELECT 1;" { t.Fatalf("got %q", sql) }
}
