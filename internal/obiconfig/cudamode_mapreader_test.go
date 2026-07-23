package config

import "testing"

func TestCudaModeTextRoundTrip(t *testing.T) {
	cases := []struct {
		in   string
		mode CudaMode
	}{
		{in: "auto", mode: CudaModeAuto},
		{in: "on", mode: CudaModeOn},
		{in: "off", mode: CudaModeOff},
	}

	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			var got CudaMode
			if err := got.UnmarshalText([]byte(tc.in)); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if got != tc.mode {
				t.Fatalf("got mode %v want %v", got, tc.mode)
			}
			raw, err := got.MarshalText()
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			if string(raw) != tc.in {
				t.Fatalf("got text %q want %q", string(raw), tc.in)
			}
		})
	}
}

func TestEBPFMapReaderTextRoundTrip(t *testing.T) {
	cases := []struct {
		in  string
		out string
		val EBPFMapReader
	}{
		{in: "", out: "auto", val: MapReaderAuto},
		{in: "auto", out: "auto", val: MapReaderAuto},
		{in: "batch", out: "batch", val: MapReaderBatch},
		{in: "legacy", out: "legacy", val: MapReaderLegacy},
	}

	for _, tc := range cases {
		t.Run(tc.out, func(t *testing.T) {
			var got EBPFMapReader
			if err := got.UnmarshalText([]byte(tc.in)); err != nil {
				t.Fatalf("unmarshal failed: %v", err)
			}
			if got != tc.val {
				t.Fatalf("got value %v want %v", got, tc.val)
			}
			raw, err := got.MarshalText()
			if err != nil {
				t.Fatalf("marshal failed: %v", err)
			}
			if string(raw) != tc.out {
				t.Fatalf("got text %q want %q", string(raw), tc.out)
			}
		})
	}
}
