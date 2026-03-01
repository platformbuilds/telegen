// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package traces

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/request"
	"github.com/mirastacklabs-ai/telegen/internal/appolly/app/svc"
	"github.com/mirastacklabs-ai/telegen/internal/obiconfig"
	"github.com/mirastacklabs-ai/telegen/internal/testutil"
	"github.com/mirastacklabs-ai/telegen/internal/traces/hostname"
	"github.com/mirastacklabs-ai/telegen/pkg/pipe/msg"
)

const testTimeout = 5 * time.Second

func TestReadDecorator(t *testing.T) {
	localHostname, _, err := hostname.CreateResolver("", "", false).Query()
	require.NoError(t, err)
	require.NotEmpty(t, localHostname)
	dnsHostname, _, err := hostname.CreateResolver("", "", true).Query()
	require.NoError(t, err)
	require.NotEmpty(t, dnsHostname)

	type testCase struct {
		desc             string
		cfg              ReadDecorator
		expectedInstance string
		expectedHN       string
	}
	for _, tc := range []testCase{{
		desc:             "dns",
		cfg:              ReadDecorator{InstanceID: config.InstanceIDConfig{HostnameDNSResolution: true}},
		expectedInstance: dnsHostname + ":1234",
		expectedHN:       dnsHostname,
	}, {
		desc:             "no-dns",
		expectedInstance: localHostname + ":1234",
		expectedHN:       localHostname,
	}, {
		desc:             "override hostname",
		cfg:              ReadDecorator{InstanceID: config.InstanceIDConfig{OverrideHostname: "foooo"}},
		expectedInstance: "foooo:1234",
		expectedHN:       "foooo",
	}} {
		t.Run(tc.desc, func(t *testing.T) {
			cfg := tc.cfg
			cfg.TracesInput = msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			cfg.DecoratedTraces = msg.NewQueue[[]request.Span](msg.ChannelBufferLen(10))
			decoratedOutput := cfg.DecoratedTraces.Subscribe()
			ctx := t.Context()
			readLoop, err := ReadFromChannel(&cfg)(ctx)
			require.NoError(t, err)
			go readLoop(ctx)
			cfg.TracesInput.Send([]request.Span{
				{Path: "/foo", Pid: request.PidInfo{HostPID: 1234}},
				{Path: "/bar", Pid: request.PidInfo{HostPID: 1234}},
			})
			outSpans := testutil.ReadChannel(t, decoratedOutput, testTimeout)
			assert.Equal(t, []request.Span{
				{
					Service: svc.Attrs{UID: svc.UID{Instance: tc.expectedInstance}, HostName: tc.expectedHN},
					Path:    "/foo", Pid: request.PidInfo{HostPID: 1234},
				},
				{
					Service: svc.Attrs{UID: svc.UID{Instance: tc.expectedInstance}, HostName: tc.expectedHN},
					Path:    "/bar", Pid: request.PidInfo{HostPID: 1234},
				},
			}, outSpans)
		})
	}
}
