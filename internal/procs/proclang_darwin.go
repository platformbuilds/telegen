// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package procs // import "github.com/platformbuilds/telegen/internal/procs"

import (
	"debug/elf"

	"github.com/platformbuilds/telegen/internal/appolly/app/svc"
)

func FindProcLanguage(_ int32) svc.InstrumentableType {
	return svc.InstrumentableGeneric
}

func FindExeSymbols(_ *elf.File, _ []string) (map[string]Sym, error) {
	return nil, nil
}
