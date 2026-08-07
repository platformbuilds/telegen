// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadCatalog loads a collector default.yaml.
func LoadCatalog(path string) (*Catalog, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Catalog
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadObjectTemplate loads and flattens an object template with per-file version best-fit.
// Harvest keeps a template only in the ONTAP version dir where it was introduced; older
// objects live in older dirs. We pick the highest version directory <= requested that
// actually contains objectFile.
func LoadObjectTemplate(baseDir, objectFile, version string) (*Template, string, error) {
	path, err := resolveTemplatePath(baseDir, objectFile, version)
	if err != nil {
		return nil, "", err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, "", err
	}
	t.RawCounters = FlattenCounters(t.Counters)
	return &t, path, nil
}

func resolveTemplatePath(baseDir, objectFile, version string) (string, error) {
	want := parseVersion(version)
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return "", err
	}

	type cand struct {
		path string
		v    versionTuple
	}
	var cands []cand
	for _, e := range entries {
		if !e.IsDir() || e.Name() == "asar2" {
			continue
		}
		v := parseVersion(e.Name())
		if !v.ok {
			continue
		}
		p := filepath.Join(baseDir, e.Name(), objectFile)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		// Prefer versions <= requested; if none, fall back to any available
		cands = append(cands, cand{path: p, v: v})
	}

	var leq []cand
	for _, c := range cands {
		if !c.v.greater(want) {
			leq = append(leq, c)
		}
	}
	pool := leq
	if len(pool) == 0 {
		pool = cands
	}
	if len(pool) == 0 {
		// flat file in baseDir
		p := filepath.Join(baseDir, objectFile)
		if _, err := os.Stat(p); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("template %s not found under %s for version %s", objectFile, baseDir, version)
	}
	sort.Slice(pool, func(i, j int) bool { return pool[i].v.less(pool[j].v) })
	return pool[len(pool)-1].path, nil
}

// BestFitASAR2 returns baseDir/asar2 if it exists.
func BestFitASAR2(baseDir string) (string, bool) {
	p := filepath.Join(baseDir, "asar2")
	if st, err := os.Stat(p); err == nil && st.IsDir() {
		return p, true
	}
	return "", false
}

type versionTuple struct {
	gen, major, minor int
	ok                bool
}

func parseVersion(s string) versionTuple {
	s = strings.TrimSpace(s)
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return versionTuple{}
	}
	g, err1 := strconv.Atoi(parts[0])
	m, err2 := strconv.Atoi(parts[1])
	min := 0
	if len(parts) > 2 {
		p := parts[2]
		for i, c := range p {
			if c < '0' || c > '9' {
				p = p[:i]
				break
			}
		}
		if parsed, err := strconv.Atoi(p); err == nil {
			min = parsed
		}
	}
	if err1 != nil || err2 != nil {
		return versionTuple{}
	}
	return versionTuple{gen: g, major: m, minor: min, ok: true}
}

func (v versionTuple) less(o versionTuple) bool {
	if v.gen != o.gen {
		return v.gen < o.gen
	}
	if v.major != o.major {
		return v.major < o.major
	}
	return v.minor < o.minor
}

func (v versionTuple) greater(o versionTuple) bool {
	return o.less(v)
}
