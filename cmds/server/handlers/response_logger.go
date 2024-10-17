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
	ctx context.Context
	loggerProvider
	next tq.Handler
}

// Write response fields to logger
func (l *ResponseLogger) Write(ctx context.Context, p []byte) (int, error) {
	packet := tq.NewPacket()
	err := packet.UnmarshalBinary(p)
	if err != nil {
		return 0, err
	}
	request := tq.Request{Header: *packet.Header, Body: packet.Body[:], Context: ctx}
	l.Record(ctx, request.Fields(tq.ContextConnRemoteAddr, tq.ContextConnLocalAddr, tq.ContextUser, tq.ContextRemoteAddr, tq.ContextReqArgs, tq.ContextAcctType, tq.ContextPrivLvl, tq.ContextPort))

	return 0, nil
}

// Handle implements a middleware logger for next
func (l *ResponseLogger) Handle(response tq.Response, request tq.Request) {
	// ResponseLogger's context should include all of contextual fields from the request
	// if the request's context was used to initialize the logger
	request.Context = l.ctx
	response.Context(l.ctx)
	response.RegisterWriter(l)
	l.next.Handle(response, request)
}

// recorder is a private interface for the handlers package.
// it lets us abstract an object which can be used to store persistent data
// also used to intercept the handler state machine. the interface would help
// to make this dependency be injectable from main in the future
type recorderWriter interface {
	RecordCtx(request *tq.Request, keys ...tq.ContextKey)
	Context() context.Context
	Write(ctx context.Context, p []byte) (int, error)
}

// ctxLogger is a middleware handler that logs responses from the server
type ctxLogger struct {
	loggerProvider
	tq.Writer
	ctx context.Context
}

// newPacketLogger is a logger scoped to a AAA handler's lifetime
func newPacketLogger(l loggerProvider) *ctxLogger {
	return &ctxLogger{loggerProvider: l, Writer: &ResponseLogger{loggerProvider: l}}
}

// Context returns the ctxLogger's stored context
// This context could be nil if this method is called before RecordCtx
func (cl *ctxLogger) Context() context.Context {
	return cl.ctx
}

// RecordCtx receives a request object, and a set of context keys
// it will call the loggerProvider's Set function to process context keys
// which store data that is supposed to be persistent for a handler's lifetime
func (cl *ctxLogger) RecordCtx(request *tq.Request, keys ...tq.ContextKey) {
	if cl.ctx == nil {
		cl.ctx = request.Context
	}
	cl.ctx = cl.Set(cl.ctx, request.Fields(), keys...)
}
