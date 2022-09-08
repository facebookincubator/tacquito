/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package local supports writing Accounting logs to the local system via a log.Logger
package local

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"

	tq "github.com/facebookincubator/tacquito"
)

// loggerProvider provides the logging implementation for local server events
type loggerProvider interface {
	Infof(ctx context.Context, format string, args ...interface{})
	Errorf(ctx context.Context, format string, args ...interface{})
}

// our log.Logger interface
type acctLogger interface {
	Printf(format string, args ...interface{})
}

// Option is the setter type for Accounter
type Option func(a *Accounter)

// SetLogSinkDefault will create a file object for writing logs to and attach it to the accounting logger
func SetLogSinkDefault(path, prefix string) Option {
	return func(a *Accounter) {
		// open file for accounting data
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return
		}
		a.sink = log.New(f, prefix, log.Ldate|log.Ltime|log.Llongfile)
	}
}

// SetLogSink will use the acctLogger interface to create a local logger
func SetLogSink(l acctLogger) Option {
	return func(a *Accounter) {
		a.sink = l
	}
}

// Accounter that writes to system log service
type Accounter struct {
	loggerProvider            // local server event logger
	sink           acctLogger // accounting log destination
}

// New creates a new accounter.
// TODO: Implement log rotation
func New(l loggerProvider, opts ...Option) (*Accounter, error) {
	a := &Accounter{loggerProvider: l}
	for _, opt := range opts {
		opt(a)
	}
	if a.sink == nil {
		return nil, fmt.Errorf("a log backend is required, please call SetLogSinkDefault or SetLogSink")
	}
	return a, nil
}

// New creates a new local file accounter
func (a Accounter) New(options map[string]string) tq.Handler {
	return &Accounter{loggerProvider: a.loggerProvider, sink: a.sink}
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
		a.Errorf(request.Context, "failed to write to accounting logger: %v", err)
		return

	}

	// log accounting data
	a.sink.Printf(string(jsonLog))

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
