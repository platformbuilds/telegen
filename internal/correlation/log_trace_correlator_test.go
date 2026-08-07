package correlation

import "testing"

func TestGlobalLogTraceCorrelatorSetThenGetReturnsInjected(t *testing.T) {
	previous := GetGlobalLogTraceCorrelator()
	t.Cleanup(func() {
		SetGlobalLogTraceCorrelator(previous)
	})

	custom := NewLogTraceCorrelator(DefaultLogTraceCorrelatorConfig())
	t.Cleanup(custom.Stop)

	SetGlobalLogTraceCorrelator(custom)
	got := GetGlobalLogTraceCorrelator()
	if got != custom {
		t.Fatalf("expected injected correlator pointer, got %#v", got)
	}
}

func TestGlobalLogTraceCorrelatorLazyInitWhenNil(t *testing.T) {
	previous := GetGlobalLogTraceCorrelator()
	t.Cleanup(func() {
		SetGlobalLogTraceCorrelator(previous)
	})

	SetGlobalLogTraceCorrelator(nil)
	got := GetGlobalLogTraceCorrelator()
	if got == nil {
		t.Fatal("expected lazy initialization to create correlator")
	}
}
