package parsers

import (
	"log/slog"
	"testing"
)

func BenchmarkPipelineParse(b *testing.B) {
	cfg := DefaultPipelineConfig()
	cfg.EnableK8sEnrichment = false
	cfg.EnableTraceContextEnrichment = false
	p := NewPipeline(cfg, slog.Default())

	lines := map[string]string{
		"runtime_docker_json": `{"log":"GET /checkout 200 13ms\n","stream":"stdout","time":"2026-01-15T10:30:45.123456789Z"}`,
		"spring_boot":         "2026-01-15 10:30:45.123 INFO [http-nio-8080-exec-1] c.example.Checkout - checkout completed",
		"log4j":               "2026-01-15 10:30:45,123 INFO [main] com.example.Checkout - checkout completed",
		"plain_text":          "checkout completed without known parser format",
	}

	b.ReportAllocs()
	for name, line := range lines {
		b.Run(name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_ = p.Parse(line, "")
			}
		})
	}
}
