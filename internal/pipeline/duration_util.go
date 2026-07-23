package pipeline

import "time"

func mustDur(s string) time.Duration {
	d, _ := time.ParseDuration(s)
	return d
}
