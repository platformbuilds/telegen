// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package template

import (
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// LoadCatalog loads a collector default.yaml.
func LoadCatalog(fsys fs.FS, name string) (*Catalog, error) {
	data, err := fs.ReadFile(fsys, name)
	if err != nil {
		return nil, err
	}
	var c Catalog
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// LoadCatalogMerged loads catalogs in order and merges their object maps. A
// later catalog overrides an object of the same name and contributes any new
// ones, so a model-specific catalog such as `rest/asar2/default.yaml` layers
// on top of the base catalog instead of replacing it. Missing catalogs after
// the first are skipped; the first must exist.
func LoadCatalogMerged(fsys fs.FS, names ...string) (*Catalog, error) {
	if len(names) == 0 {
		return nil, fmt.Errorf("no catalog specified")
	}
	base, err := LoadCatalog(fsys, names[0])
	if err != nil {
		return nil, err
	}
	merged := &Catalog{
		Collector: base.Collector,
		Schedule:  base.Schedule,
		Objects:   make(map[string]string, len(base.Objects)),
	}
	for k, v := range base.Objects {
		merged.Objects[k] = v
	}
	for _, name := range names[1:] {
		overlay, err := LoadCatalog(fsys, name)
		if err != nil {
			continue
		}
		for k, v := range overlay.Objects {
			merged.Objects[k] = v
		}
	}
	return merged, nil
}

// LoadObjectTemplateFrom resolves an object template against an ordered list of
// base directories, returning the first that yields a template. A model
// specific tree such as `rest/asar2` holds only the objects that differ, so
// every other object must fall back to the base tree rather than be dropped.
func LoadObjectTemplateFrom(fsys fs.FS, bases []string, objectFile, version string) (*Template, string, error) {
	if len(bases) == 0 {
		return nil, "", fmt.Errorf("no template base directory specified")
	}
	var firstErr error
	for _, base := range bases {
		tmpl, path, err := LoadObjectTemplate(fsys, base, objectFile, version)
		if err == nil {
			return tmpl, path, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	return nil, "", firstErr
}

// LoadObjectTemplate loads and flattens an object template with per-file version best-fit.
// Harvest keeps a template only in the ONTAP version dir where it was introduced; older
// objects live in older dirs. We pick the highest version directory <= requested that
// actually contains objectFile.
func LoadObjectTemplate(fsys fs.FS, baseDir, objectFile, version string) (*Template, string, error) {
	tmplPath, err := resolveTemplatePath(fsys, baseDir, objectFile, version)
	if err != nil {
		return nil, "", err
	}
	data, err := fs.ReadFile(fsys, tmplPath)
	if err != nil {
		return nil, "", err
	}
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, "", err
	}
	t.RawCounters = FlattenCounters(t.Counters)
	t.HiddenFields, t.CounterFilter = ExtractDirectives(t.Counters)
	return &t, tmplPath, nil
}

// QueryFilter merges the top-level `filter` block with the counters-block
// `filter` directive, matching Harvest's precedence-free union.
func (t *Template) QueryFilter() []string {
	if len(t.CounterFilter) == 0 {
		return t.Filter
	}
	out := make([]string, 0, len(t.Filter)+len(t.CounterFilter))
	out = append(out, t.Filter...)
	return append(out, t.CounterFilter...)
}

// IsPublicAPI reports whether a query targets ONTAP's public REST surface.
// The private CLI passthrough rejects the `fields` values that hidden_fields
// contributes, so Harvest only applies them to public endpoints.
func IsPublicAPI(query string) bool {
	return !strings.Contains(query, "private")
}

func resolveTemplatePath(fsys fs.FS, baseDir, objectFile, version string) (string, error) {
	want := parseVersion(version)
	entries, err := fs.ReadDir(fsys, baseDir)
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
		p := path.Join(baseDir, e.Name(), objectFile)
		if _, err := fs.Stat(fsys, p); err != nil {
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
		p := path.Join(baseDir, objectFile)
		if _, err := fs.Stat(fsys, p); err == nil {
			return p, nil
		}
		return "", fmt.Errorf("template %s not found under %s for version %s", objectFile, baseDir, version)
	}
	sort.Slice(pool, func(i, j int) bool { return pool[i].v.less(pool[j].v) })
	return pool[len(pool)-1].path, nil
}

// BestFitASAR2 returns baseDir/asar2 if it exists.
func BestFitASAR2(fsys fs.FS, baseDir string) (string, bool) {
	p := path.Join(baseDir, "asar2")
	if st, err := fs.Stat(fsys, p); err == nil && st.IsDir() {
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
