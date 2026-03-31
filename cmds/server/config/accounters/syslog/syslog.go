/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package syslog supports ending Accounting data  in JSON format to syslog
// Windows is unsupported
package syslog

import (
	"context"
	"encoding/json"
	"log/syslog"

	tq "github.com/facebookincubator/tacquito"
)

// loggerProvider provides the logging implementation for local server events
type loggerProvider interface {
	Infof(ctx context.Context, format string, args ...interface{})
	Errorf(ctx context.Context, format string, args ...interface{})
}

// Accounter that writes to system log service
type Accounter struct {
	loggerProvider // local server event logger
	*syslog.Writer // syslog writer
}

func NewDefaultWriter() (*syslog.Writer, error) {
	return syslog.New(syslog.LOG_INFO, "tacquito")
}

// New ...
func New(l loggerProvider, writer *syslog.Writer) *Accounter {
	return &Accounter{loggerProvider: l, Writer: writer}
}

// New creates a new syslog accounter
func (a Accounter) New(options map[string]string) tq.Handler {
	return &Accounter{loggerProvider: a.loggerProvider, Writer: a.Writer}
}

// Handle ...
func (a Accounter) Handle(response tq.Response, request tq.Request) {
	var body tq.AcctRequest
	if err := tq.Unmarshal(request.Body, &body); err != nil {
		response.Reply(
			tq.NewAcctReply(
				tq.SetAcctReplyStatus(tq.AcctReplyStatusError),
				tq.SetAcctReplyServerMsg("accounting failure"),
			),
		)
		return
	}

	jsonLog, err := json.Marshal(body)
	if err != nil {
		response.Reply(
			tq.NewAcctReply(
				tq.SetAcctReplyStatus(tq.AcctReplyStatusError),
				tq.SetAcctReplyServerMsg("failed to log accounting message"),
			),
		)
		a.Errorf(request.Context, "failed marshal accounting log: %v", err)
		return

	}

	// log accounting data
	if _, err := a.Write(jsonLog); err != nil {
		response.Reply(
			tq.NewAcctReply(
				tq.SetAcctReplyStatus(tq.AcctReplyStatusError),
				tq.SetAcctReplyServerMsg("failed to log accounting message"),
			),
		)
		a.Errorf(request.Context, "failed to write accounting data to syslog: %v", err)
		return

	}

	// use bitmask checks to match flag combinations, mirroring tac_plus behavior.
	// stop takes priority over start, which takes priority over watchdog.
	switch {
	case body.Flags.Has(tq.AcctFlagStop):
		response.Reply(
			tq.NewAcctReply(
				tq.SetAcctReplyStatus(tq.AcctReplyStatusSuccess),
				tq.SetAcctReplyServerMsg("success, logging stopped"),
			),
		)
	case body.Flags.Has(tq.AcctFlagStart):
		if body.Flags.Has(tq.AcctFlagWatchdog) {
			response.Reply(
				tq.NewAcctReply(
					tq.SetAcctReplyStatus(tq.AcctReplyStatusSuccess),
					tq.SetAcctReplyServerMsg("success, watchdog update"),
				),
			)
		} else {
			response.Reply(
				tq.NewAcctReply(
					tq.SetAcctReplyStatus(tq.AcctReplyStatusSuccess),
					tq.SetAcctReplyServerMsg("success, logging started"),
				),
			)
		}
	case body.Flags.Has(tq.AcctFlagWatchdog):
		response.Reply(
			tq.NewAcctReply(
				tq.SetAcctReplyStatus(tq.AcctReplyStatusSuccess),
				tq.SetAcctReplyServerMsg("success, watchdog"),
			),
		)
	default:
		a.Errorf(request.Context, "unexpected accounting flag [%v]", body.Flags)
		response.Reply(
			tq.NewAcctReply(
				tq.SetAcctReplyStatus(tq.AcctReplyStatusError),
				tq.SetAcctReplyServerMsg("unexpected accounting flag"),
			),
		)
	}
}
