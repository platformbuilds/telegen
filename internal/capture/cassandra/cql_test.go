package cassandra

import "testing"

func TestCQLParse(t *testing.T){
    ok, stmt := CQL{}.TryParseQuery([]byte("SELECT * FROM ks.tbl WHERE id=1;"))
    if !ok { t.Fatalf("expected ok") }
    if stmt == "" || stmt[:6] != "SELECT" { t.Fatalf("unexpected stmt: %q", stmt) }
    if ok2, _ := CQL{}.TryParseQuery([]byte("not cql")); ok2 {
        t.Fatalf("should not detect non-CQL")
    }
}
