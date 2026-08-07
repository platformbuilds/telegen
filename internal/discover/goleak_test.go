package discover

import (
	"testing"

	"go.uber.org/goleak"
)

func TestMain(m *testing.M) {
	goleak.VerifyTestMain(m,
		// Discover package caches use expirable LRU instances with janitor
		// goroutines scoped to package lifetime across tests.
		goleak.IgnoreTopFunction("github.com/hashicorp/golang-lru/v2/expirable.NewLRU[...].func1"),
	)
}
