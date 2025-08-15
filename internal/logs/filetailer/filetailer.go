package filetailer

import (
    "bufio"
    "encoding/json"
    "os"
    "path/filepath"
    "time"

    sdklog "go.opentelemetry.io/otel/sdk/log"
    "go.opentelemetry.io/otel/sdk/resource"
)

type Tailer struct {
    paths        []string
    positionFile string
    lp           *sdklog.LoggerProvider
}

func New(globs []string, positionFile string, lp *sdklog.LoggerProvider) *Tailer {
    return &Tailer{ paths: globs, positionFile: positionFile, lp: lp }
}

func (t *Tailer) Run(stop <-chan struct{}) error {
    if t.lp == nil { return nil }
    tick := time.NewTicker(10 * time.Second); defer tick.Stop()
    for {
        select {
        case <-tick.C:
            for _, g := range t.paths {
                matches, _ := filepath.Glob(g)
                for _, p := range matches { t.tailOnce(p) }
            }
        case <-stop: return nil
        }
    }
}

func (t *Tailer) tailOnce(path string) {
    f, err := os.Open(path); if err != nil { return }; defer f.Close()
    stat, _ := f.Stat()
    if stat.Size() > 4096 { f.Seek(stat.Size()-4096, 0) }
    sc := bufio.NewScanner(f)
    logger := t.lp.Logger("filelog", sdklog.WithResource(resource.Empty()))
    for sc.Scan() {
        line := sc.Text()
        rec := sdklog.Record{}
        rec.SetTimestamp(time.Now()); rec.SetObservedTimestamp(time.Now())
        rec.SetBody(sdklog.StringValue(line))
        var js map[string]any
        if json.Unmarshal([]byte(line), &js) == nil { rec.Attributes().PutStr("body.format","json") } else { rec.Attributes().PutStr("body.format","text") }
        rec.Attributes().PutStr("file.path", path)
        logger.Emit(rec)
    }
}
