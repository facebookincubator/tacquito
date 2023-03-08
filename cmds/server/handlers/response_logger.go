/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package handlers

import (
	"context"

	tq "github.com/facebookincubator/tacquito"
)

// NewResponseLogger will wrap another handler as middleware.  Next is the actual handler
// that will be called by the server.
func NewResponseLogger(ctx context.Context, l loggerProvider, next tq.Handler) *ResponseLogger {
	return &ResponseLogger{ctx: ctx, loggerProvider: l, next: next}
}

// ResponseLogger is a middleware handler that logs responses from the server
type ResponseLogger struct {
	loggerProvider
	ctx  context.Context
	next tq.Handler
}

// Write response fields to logger
func (l *ResponseLogger) Write(p []byte) (int, error) {
	packet := tq.NewPacket()
	err := packet.UnmarshalBinary(p)
	if err != nil {
		return 0, err
	}
	request := tq.Request{Header: *packet.Header, Body: packet.Body[:], Context: l.ctx}
	l.Record(l.ctx, request.Fields(tq.ContextConnRemoteAddr, tq.ContextUser, tq.ContextRemoteAddr, tq.ContextReqArgs, tq.ContextAcctType, tq.ContextPrivLvl, tq.ContextPort))

	return 0, nil
}

// Handle implements a middleware logger for next
func (l *ResponseLogger) Handle(response tq.Response, request tq.Request) {
	response.RegisterWriter(l)
	l.next.Handle(response, request)
}

// NewCtxLogger will wrap another handler as middleware.  Next is the actual handler
// that will be called by the server after being wrapped inside a response logger
func NewCtxLogger(l loggerProvider, request tq.Request, next tq.Handler) *CtxLogger {
	return &CtxLogger{loggerProvider: l, req: request, next: next}
}

// CtxLogger is a middleware handler that logs responses from the server
type CtxLogger struct {
	loggerProvider
	req  tq.Request
	next tq.Handler
}

// Gather will get fields from a request
func (al *CtxLogger) Gather() {
	fields := al.req.Fields()
	switch fields["packet-type"] {
	case "AuthenStart":
		if v, ok := fields["user"]; ok && v != "" {
			al.req.Context = context.WithValue(al.req.Context, tq.ContextUser, v)
		}
		al.req.Context = context.WithValue(al.req.Context, tq.ContextRemoteAddr, fields["rem-addr"])
		al.req.Context = context.WithValue(al.req.Context, tq.ContextPort, fields["port"])
		al.req.Context = context.WithValue(al.req.Context, tq.ContextPrivLvl, fields["priv-lvl"])

	case "AuthenContinue":
		if v, ok := fields["user-msg"]; ok && v != "" {
			al.req.Context = context.WithValue(al.req.Context, tq.ContextUser, v)
		}
	case "AcctRequest":
		al.req.Context = context.WithValue(al.req.Context, tq.ContextUser, fields["user"])
		al.req.Context = context.WithValue(al.req.Context, tq.ContextRemoteAddr, fields["rem-addr"])
		al.req.Context = context.WithValue(al.req.Context, tq.ContextReqArgs, fields["args"])
		al.req.Context = context.WithValue(al.req.Context, tq.ContextAcctType, fields["type"])
		al.req.Context = context.WithValue(al.req.Context, tq.ContextPort, fields["port"])
		al.req.Context = context.WithValue(al.req.Context, tq.ContextPrivLvl, fields["priv-lvl"])
	case "AuthorRequest":
		al.req.Context = context.WithValue(al.req.Context, tq.ContextUser, fields["user"])
		al.req.Context = context.WithValue(al.req.Context, tq.ContextRemoteAddr, fields["rem-addr"])
		al.req.Context = context.WithValue(al.req.Context, tq.ContextReqArgs, fields["args"])
		al.req.Context = context.WithValue(al.req.Context, tq.ContextPort, fields["port"])
		al.req.Context = context.WithValue(al.req.Context, tq.ContextPrivLvl, fields["priv-lvl"])
	}
}

// Handle implements a middleware logger for next
func (al *CtxLogger) Handle(response tq.Response, request tq.Request) {
	al.Gather()
	request.Context = al.req.Context
	switch request.Header.Type {
	case tq.Authenticate:
		r := NewResponseLogger(request.Context, al.loggerProvider, al.next)
		r.Handle(response, request)
	case tq.Accounting, tq.Authorize:
		response.PopWriter() // this replaces the existing response logger object with the one below
		r := NewResponseLogger(request.Context, al.loggerProvider, al.next)
		r.Handle(response, request)
	default:
		al.Infof(request.Context, "[%v] unknown packet code detected: %v", request.Header.SessionID, request.Header.Type)
		al.next.Handle(response, request)
	}

}
