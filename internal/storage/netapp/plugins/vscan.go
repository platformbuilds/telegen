// Copyright The Telegen Authors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"log/slog"
	"strings"

	"github.com/mirastacklabs-ai/telegen/internal/storage/netapp/matrix"
)

// VscanNames are the three identifiers ONTAP packs into a vscan instance name.
type VscanNames struct {
	Node    string
	Svm     string
	Scanner string
}

// SplitVscanName decomposes an ONTAP vscan instance name into its parts. The
// name is a colon-separated triple whose field order differs by API:
//
//	REST : node : svm : scanner   e.g. sti46-vsim-ucs519d:vs0:172.29.120.57
//	ZAPI : svm  : scanner : node  e.g. vs_test4:2.2.2.2:umeng-aff300-05
//
// The scanner is an address that may itself contain colons when it is IPv6, so
// the split anchors on the first and last colon rather than splitting on all
// of them.
func SplitVscanName(ontapName string, isZapi bool) (VscanNames, bool) {
	firstColon := strings.Index(ontapName, ":")
	lastColon := strings.LastIndex(ontapName, ":")
	if firstColon == -1 || firstColon == lastColon {
		return VscanNames{}, false
	}
	if isZapi {
		return VscanNames{
			Svm:     ontapName[:firstColon],
			Scanner: ontapName[firstColon+1 : lastColon],
			Node:    ontapName[lastColon+1:],
		}, true
	}
	return VscanNames{
		Node:    ontapName[:firstColon],
		Svm:     ontapName[firstColon+1 : lastColon],
		Scanner: ontapName[lastColon+1:],
	}, true
}

// Vscan splits the packed vscan instance name into node / svm / scanner
// labels. The vscan templates declare those three as instance keys but no
// counter produces them — ONTAP only reports the joined name — so without this
// plugin every vscan series would export unlabelled.
func Vscan(mat *matrix.Matrix, _ any, log *slog.Logger) *matrix.Matrix {
	if mat == nil {
		return nil
	}
	for _, inst := range mat.Instances {
		name := inst.Labels["id"]
		if name == "" {
			name = inst.Key
		}
		names, ok := SplitVscanName(name, false)
		if !ok {
			if log != nil {
				log.Debug("vscan: unparseable instance name", "name", name)
			}
			continue
		}
		inst.Labels["node"] = names.Node
		inst.Labels["svm"] = names.Svm
		inst.Labels["scanner"] = names.Scanner
	}
	return mat
}
