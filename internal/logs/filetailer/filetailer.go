package filetailer

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	otellog "go.opentelemetry.io/otel/log" // API types for Record/KeyValue/Value
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

type Tailer struct {
	paths        []string
	positionFile string
	lp           *sdklog.LoggerProvider
}

func New(globs []string, positionFile string, lp *sdklog.LoggerProvider) *Tailer {
	return &Tailer{paths: globs, positionFile: positionFile, lp: lp}
}

func (t *Tailer) Run(stop <-chan struct{}) error {
	if t.lp == nil {
		return nil
	}
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-tick.C:
			for _, g := range t.paths {
				matches, _ := filepath.Glob(g)
				for _, p := range matches {
					t.tailOnce(p)
				}
			}
		case <-stop:
			return nil
		}
	}
}

func (t *Tailer) tailOnce(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	stat, _ := f.Stat()
	if stat.Size() > 4096 {
		_, _ = f.Seek(stat.Size()-4096, 0)
	}

	sc := bufio.NewScanner(f)

	// sdk/log v0.3.0: provider produces a Logger that implements otel/log.Logger
	logger := t.lp.Logger("filelog")

	for sc.Scan() {
		line := sc.Text()

		// Build an otel/log.Record (NOT sdk/log.Record)
		rec := otellog.Record{}
		now := time.Now()
		rec.SetTimestamp(now)
		rec.SetObservedTimestamp(now)
		rec.SetBody(otellog.StringValue(line))

		// Add otel/log.KeyValue attributes
		var js map[string]any
		if json.Unmarshal([]byte(line), &js) == nil {
			rec.AddAttributes(otellog.String("body.format", "json"))
		} else {
			rec.AddAttributes(otellog.String("body.format", "text"))
		}
		rec.AddAttributes(otellog.String("file.path", path))

		// Emit via the API logger
		logger.Emit(context.Background(), rec)
	}
}
