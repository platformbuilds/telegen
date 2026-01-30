package filetailer

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"go.opentelemetry.io/otel/log"
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
		f.Seek(stat.Size()-4096, 0)
	}
	sc := bufio.NewScanner(f)
	logger := t.lp.Logger("filelog")
	ctx := context.Background()
	for sc.Scan() {
		line := sc.Text()
		var rec log.Record
		rec.SetTimestamp(time.Now())
		rec.SetBody(log.StringValue(line))
		var js map[string]any
		if json.Unmarshal([]byte(line), &js) == nil {
			rec.AddAttributes(log.String("body.format", "json"))
		} else {
			rec.AddAttributes(log.String("body.format", "text"))
		}
		rec.AddAttributes(log.String("file.path", path))
		logger.Emit(ctx, rec)
	}
}
