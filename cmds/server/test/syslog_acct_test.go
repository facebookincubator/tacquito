/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"context"
	"fmt"
	"log/syslog"
	"net"
	"testing"

	tq "github.com/facebookincubator/tacquito"
	syslogacct "github.com/facebookincubator/tacquito/cmds/server/config/accounters/syslog"
	"github.com/stretchr/testify/assert"
)

// syslogAcctLogger satisfies the syslog accounter's loggerProvider interface
type syslogAcctLogger struct {
	errors []string
}

func (m *syslogAcctLogger) Infof(_ string, _ ...interface{}) {}
func (m *syslogAcctLogger) Errorf(format string, args ...interface{}) {
	m.errors = append(m.errors, fmt.Sprintf(format, args...))
}

func syslogMakeFlag(flags ...tq.AcctRequestFlag) tq.AcctRequestFlag {
	var f tq.AcctRequestFlag
	for _, flag := range flags {
		f.Set(flag)
	}
	return f
}

func newTestSyslogWriter(t *testing.T) *syslog.Writer {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	assert.NoError(t, err)
	t.Cleanup(func() { conn.Close() })

	writer, err := syslog.Dial("udp", conn.LocalAddr().String(), syslog.LOG_INFO, "tacquito-test")
	assert.NoError(t, err)
	t.Cleanup(func() { writer.Close() })
	return writer
}

func newSyslogTestAccounter(t *testing.T) (tq.Handler, *syslogAcctLogger) {
	t.Helper()
	logger := &syslogAcctLogger{}
	writer := newTestSyslogWriter(t)
	return syslogacct.New(logger, writer), logger
}

func syslogMakeRequest(t *testing.T, flags tq.AcctRequestFlag) tq.Request {
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

func TestSyslogHandleAcctFlags(t *testing.T) {
	tests := []struct {
		name          string
		flags         tq.AcctRequestFlag
		wantStatus    tq.AcctReplyStatus
		wantServerMsg tq.AcctServerMsg
	}{
		{
			name:          "start flag",
			flags:         syslogMakeFlag(tq.AcctFlagStart),
			wantStatus:    tq.AcctReplyStatusSuccess,
			wantServerMsg: "success, logging started",
		},
		{
			name:          "stop flag",
			flags:         syslogMakeFlag(tq.AcctFlagStop),
			wantStatus:    tq.AcctReplyStatusSuccess,
			wantServerMsg: "success, logging stopped",
		},
		{
			name:          "watchdog flag",
			flags:         syslogMakeFlag(tq.AcctFlagWatchdog),
			wantStatus:    tq.AcctReplyStatusSuccess,
			wantServerMsg: "success, watchdog",
		},
		{
			name:          "stop and start combined - stop takes priority",
			flags:         syslogMakeFlag(tq.AcctFlagStop, tq.AcctFlagStart),
			wantStatus:    tq.AcctReplyStatusSuccess,
			wantServerMsg: "success, logging stopped",
		},
		{
			name:          "start and watchdog combined - watchdog update",
			flags:         syslogMakeFlag(tq.AcctFlagStart, tq.AcctFlagWatchdog),
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
			a, _ := newSyslogTestAccounter(t)
			resp := newMockedResponse()
			req := syslogMakeRequest(t, tt.flags)
			a.Handle(resp, req)

			reply, ok := resp.got.(*tq.AcctReply)
			assert.True(t, ok)
			assert.Equal(t, tt.wantStatus, reply.Status)
			assert.Equal(t, tt.wantServerMsg, reply.ServerMsg)
		})
	}
}
