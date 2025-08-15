package kafka

import "testing"

func TestMaybeKafka(t *testing.T) {
	if MaybeKafka([]byte{0x00, 0x12}) != true {
		t.Fatalf("expected true")
	}
	if MaybeKafka([]byte{0x01}) {
		t.Fatalf("expected false")
	}
}
