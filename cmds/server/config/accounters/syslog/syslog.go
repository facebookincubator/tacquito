/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package syslog supports ending Accounting data  in JSON format to syslog
// Windows is unsupported
package syslog

import (
	"encoding/json"
	"log/syslog"

	tq "github.com/facebookincubator/tacquito"
)

// loggerProvider provides the logging implementation for local server events
type loggerProvider interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// Accounter that writes to system log service
type Accounter struct {
	loggerProvider // local server event logger
	*syslog.Writer // syslog writer
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
		a.Errorf("failed marshal accounting log: %v", err)
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
		a.Errorf("failed to write accounting data to syslog: %v", err)
		return

	}

	// start/stop/watchdog don't actually log anything, this is up to you
	switch body.Flags {
	case tq.AcctFlagStart:
		response.Reply(
			tq.NewAcctReply(
				tq.SetAcctReplyStatus(tq.AcctReplyStatusSuccess),
				tq.SetAcctReplyServerMsg("success, logging started"),
			),
		)
		return
	case tq.AcctFlagStop:
		response.Reply(
			tq.NewAcctReply(
				tq.SetAcctReplyStatus(tq.AcctReplyStatusSuccess),
				tq.SetAcctReplyServerMsg("success, logging stopped"),
			),
		)
		return
	case tq.AcctFlagWatchdog:
		if int(request.Header.SeqNo) != 1 {
			// cannot be seqno > 1
			response.Reply(
				tq.NewAcctReply(
					tq.SetAcctReplyStatus(tq.AcctReplyStatusError),
					tq.SetAcctReplyServerMsg("invalid sequence number"),
				),
			)
			return
		}
		response.Reply(
			tq.NewAcctReply(
				tq.SetAcctReplyStatus(tq.AcctReplyStatusSuccess),
				tq.SetAcctReplyServerMsg("success, watchdog"),
			),
		)
		return
	case tq.AcctFlagWatchdogWithUpdate:
		if int(request.Header.SeqNo) < 3 {
			// cannot be seqno 1 or 2
			response.Reply(
				tq.NewAcctReply(
					tq.SetAcctReplyStatus(tq.AcctReplyStatusError),
					tq.SetAcctReplyServerMsg("invalid sequence number"),
				),
			)
			return
		}
		response.Reply(
			tq.NewAcctReply(
				tq.SetAcctReplyStatus(tq.AcctReplyStatusSuccess),
				tq.SetAcctReplyServerMsg("success, watchdog update"),
			),
		)
		return
	}
	response.Reply(
		tq.NewAcctReply(
			tq.SetAcctReplyStatus(tq.AcctReplyStatusError),
			tq.SetAcctReplyServerMsg("unexpected accounting flag"),
		),
	)
}
