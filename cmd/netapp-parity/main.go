// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/catalog"
)

// netapp-parity enumerates Harvest-compatible metric names from Telegen templates
// (including Aggregator/Max/plugin expansion) and diffs against Harvest ontap_metrics.json.
func main() {
	templatesDir := flag.String("templates", "configs/netapp", "Telegen NetApp templates dir")
	harvestJSON := flag.String("harvest-json", "", "Path to Harvest mcp/metadata/ontap_metrics.json")
	allowlistPath := flag.String("allowlist", "configs/netapp/parity-allowlist.txt", "Allowed missing metrics (must stay empty for full parity)")
	version := flag.String("version", "9.16.1", "ONTAP version for template resolution")
	verbose := flag.Bool("v", false, "verbose")
	flag.Parse()

	telegenNames, err := catalog.Expand(catalog.ExpandOptions{
		TemplatesDir: *templatesDir,
		Version:      *version,
		IncludeASAr2: true,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "enumerate telegen: %v\n", err)
		os.Exit(2)
	}
	fmt.Printf("telegen template metric families: %d\n", len(telegenNames))
	if *verbose {
		names := make([]string, 0, len(telegenNames))
		for n := range telegenNames {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Println("TELEGEN", n)
		}
	}

	if *harvestJSON == "" {
		fmt.Println("no -harvest-json provided; listing only")
		return
	}
	harvestNames, err := loadHarvestNames(*harvestJSON)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load harvest json: %v\n", err)
		os.Exit(2)
	}
	allow := loadAllowlist(*allowlistPath)
	if len(allow) > 0 {
		fmt.Fprintf(os.Stderr, "parity-allowlist.txt has %d entries; full parity requires an empty allowlist\n", len(allow))
	}
	missing := []string{}
	for _, h := range harvestNames {
		if _, ok := telegenNames[h]; ok {
			continue
		}
		if allow[h] {
			continue
		}
		missing = append(missing, h)
	}
	sort.Strings(missing)
	fmt.Printf("harvest families: %d\n", len(harvestNames))
	fmt.Printf("missing (not allowlisted): %d\n", len(missing))
	for _, m := range missing {
		fmt.Println("MISSING", m)
	}
	if len(missing) > 0 {
		os.Exit(1)
	}
	if len(allow) > 0 {
		fmt.Fprintln(os.Stderr, "parity OK against harvest, but allowlist is non-empty — clear configs/netapp/parity-allowlist.txt")
		os.Exit(1)
	}
	fmt.Println("parity OK")
}

func loadHarvestNames(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw any
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	set := map[string]struct{}{}
	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			switch t := item.(type) {
			case string:
				set[t] = struct{}{}
			case map[string]any:
				if n, ok := t["name"].(string); ok {
					set[n] = struct{}{}
				} else if n, ok := t["metric"].(string); ok {
					set[n] = struct{}{}
				}
			}
		}
	case map[string]any:
		for k, val := range v {
			if k == "metrics" {
				if arr, ok := val.([]any); ok {
					for _, item := range arr {
						if m, ok := item.(map[string]any); ok {
							if n, ok := m["name"].(string); ok {
								set[n] = struct{}{}
							}
						} else if s, ok := item.(string); ok {
							set[s] = struct{}{}
						}
					}
				}
			} else {
				set[k] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, nil
}

func loadAllowlist(path string) map[string]bool {
	out := map[string]bool{}
	data, err := os.ReadFile(path)
	if err != nil {
		return out
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out[line] = true
	}
	return out
}
