// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package ebpfcommon // import "github.com/mirastacklabs-ai/telegen/internal/ebpf/common"

import (
	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/ringbuf"
)

type pendingSpanLinks struct{}

func readGoChannelLinkEvent(parseCtx *EBPFParseContext, record *ringbuf.Record) (request.Span, bool, error) {
	if parseCtx == nil {
		return request.Span{}, true, nil
	}

	event, err := ReinterpretCast[GoChannelLinkTrace](record.RawSample)
	if err != nil {
		return request.Span{}, true, err
	}

	_ = event
	return request.Span{}, true, nil
}

func (ctx *EBPFParseContext) ensurePendingSpanLinks() *pendingSpanLinks {
	if ctx.pendingSpanLinks == nil {
		ctx.pendingSpanLinks = &pendingSpanLinks{}
	}
	return ctx.pendingSpanLinks
}

func (ctx *EBPFParseContext) consumePendingSpanLinks(_ *request.Span) {
}
