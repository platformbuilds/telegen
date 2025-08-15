package cassandra

import "testing"

func TestCQL_TryParseQuery(t *testing.T) {
	tests := []struct {
		name   string
		in     string
		ok     bool
		expect string // expected stmt (after TrimSpace)
	}{
		{
			name:   "SELECT with semicolon",
			in:     "SELECT * FROM ks.tbl WHERE id=1;",
			ok:     true,
			expect: "SELECT * FROM ks.tbl WHERE id=1;",
		},
		{
			name:   "INSERT lowercase no semicolon",
			in:     "insert into ks.tbl (a) values (1)",
			ok:     true,
			expect: "insert into ks.tbl (a) values (1)",
		},
		{
			name:   "DELETE with leading/trailing whitespace",
			in:     "   delete from t where x=1;   ",
			ok:     true,
			expect: "delete from t where x=1;",
		},
		{
			name:   "Arbitrary text ending with semicolon passes (naive rule)",
			in:     "not really cql;",
			ok:     true,
			expect: "not really cql;",
		},
		{
			name:   "Non-CQL without semicolon rejected",
			in:     "ping",
			ok:     false,
			expect: "",
		},
		{
			name:   "Empty rejected",
			in:     "",
			ok:     false,
			expect: "",
		},
	}

	var p CQL
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ok, stmt := p.TryParseQuery([]byte(tc.in))
			if ok != tc.ok {
				t.Fatalf("ok=%v, want %v (input %q)", ok, tc.ok, tc.in)
			}
			if stmt != tc.expect {
				t.Fatalf("stmt=%q, want %q", stmt, tc.expect)
			}
		})
	}
}
