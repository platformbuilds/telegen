package cassandra

import "strings"

type CQL struct{}

func (CQL) TryParseQuery(buf []byte) (ok bool, stmt string) {
    s := strings.TrimSpace(string(buf))
    if s == "" { return false, "" }
    // naive: treat as CQL if ends with semicolon or starts with SELECT/INSERT/UPDATE/DELETE
    upper := strings.ToUpper(s)
    if strings.HasSuffix(upper, ";") || strings.HasPrefix(upper, "SELECT ") || strings.HasPrefix(upper, "INSERT ") || strings.HasPrefix(upper, "UPDATE ") || strings.HasPrefix(upper, "DELETE ") {
        return true, s
    }
    return false, ""
}
