/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"context"
	"fmt"
	"testing"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config/accounters/local"
	"github.com/stretchr/testify/assert"
)

// localAcctLogger satisfies the local accounter's loggerProvider interface
type localAcctLogger struct {
	errors []string
}

func (m *localAcctLogger) Infof(_ context.Context, _ string, _ ...interface{}) {}
func (m *localAcctLogger) Errorf(_ context.Context, format string, args ...interface{}) {
	m.errors = append(m.errors, fmt.Sprintf(format, args...))
}

// localAcctSink satisfies the local accounter's acctLogger interface
type localAcctSink struct {
	messages []string
}

func (m *localAcctSink) Printf(format string, args ...interface{}) {
	m.messages = append(m.messages, fmt.Sprintf(format, args...))
}

func localMakeFlag(flags ...tq.AcctRequestFlag) tq.AcctRequestFlag {
	var f tq.AcctRequestFlag
	for _, flag := range flags {
		f.Set(flag)
	}
	return f
}

func localMakeRequest(t *testing.T, flags tq.AcctRequestFlag) tq.Request {
	t.Helper()
	body := tq.NewAcctRequest(
		tq.SetAcctRequestFlag(flags),
		tq.SetAcctRequestMethod(tq.AuthenMethodTacacsPlus),
		tq.SetAcctRequestPrivLvl(tq.PrivLvlRoot),
		tq.SetAcctRequestType(tq.AuthenTypeASCII),
		tq.SetAcctRequestService(tq.AuthenServiceLogin),
		tq.SetAcctRequestUser("testuser"),
	)
	b, err := body.MarshalBinary()
	assert.NoError(t, err)
	return tq.Request{
		Header: *tq.NewHeader(
			tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
			tq.SetHeaderType(tq.Accounting),
			tq.SetHeaderSessionID(1),
		),
		Body:    b,
		Context: context.Background(),
	}
}

func newLocalTestAccounter(t *testing.T) (tq.Handler, *localAcctLogger, *localAcctSink) {
	t.Helper()
	logger := &localAcctLogger{}
	sink := &localAcctSink{}
	a, err := local.New(logger, local.SetLogSink(sink))
	assert.NoError(t, err)
	return a, logger, sink
}

func TestLocalHandleAcctFlags(t *testing.T) {
	tests := []struct {
		name          string
		flags         tq.AcctRequestFlag
		wantStatus    tq.AcctReplyStatus
		wantServerMsg tq.AcctServerMsg
	}{
		{
			name:          "start flag",
			flags:         localMakeFlag(tq.AcctFlagStart),
			wantStatus:    tq.AcctReplyStatusSuccess,
			wantServerMsg: "success, logging started",
		},
		{
			name:          "stop flag",
			flags:         localMakeFlag(tq.AcctFlagStop),
			wantStatus:    tq.AcctReplyStatusSuccess,
			wantServerMsg: "success, logging stopped",
		},
		{
			name:          "watchdog flag",
			flags:         localMakeFlag(tq.AcctFlagWatchdog),
			wantStatus:    tq.AcctReplyStatusSuccess,
			wantServerMsg: "success, watchdog",
		},
		{
			name:          "stop and start combined - stop takes priority",
			flags:         localMakeFlag(tq.AcctFlagStop, tq.AcctFlagStart),
			wantStatus:    tq.AcctReplyStatusSuccess,
			wantServerMsg: "success, logging stopped",
		},
		{
			name:          "start and watchdog combined - watchdog update",
			flags:         localMakeFlag(tq.AcctFlagStart, tq.AcctFlagWatchdog),
			wantStatus:    tq.AcctReplyStatusSuccess,
			wantServerMsg: "success, watchdog update",
		},
		{
			name:          "watchdog with update constant",
			flags:         tq.AcctFlagWatchdogWithUpdate,
			wantStatus:    tq.AcctReplyStatusSuccess,
			wantServerMsg: "success, watchdog update",
		},
		{
			name:          "no flags - unexpected",
			flags:         tq.AcctRequestFlag(0),
			wantStatus:    tq.AcctReplyStatusError,
			wantServerMsg: "unexpected accounting flag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, _, _ := newLocalTestAccounter(t)
			resp := newMockedResponse()
			req := localMakeRequest(t, tt.flags)
			a.Handle(resp, req)

			reply, ok := resp.got.(*tq.AcctReply)
			assert.True(t, ok)
			assert.Equal(t, tt.wantStatus, reply.Status)
			assert.Equal(t, tt.wantServerMsg, reply.ServerMsg)
		})
	}
}
