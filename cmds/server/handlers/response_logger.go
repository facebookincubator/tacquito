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
	response.RegisterWriter(l)
	l.next.Handle(response, request)
}

// recorder is a private interface for the handlers package.
// it lets us abstract an object which can be used to store persistent data
// also used to intercept the handler state machine. the interface would help
// to make this dependency be injectable from main in the future
type recorder interface {
	RecordCtx(request *tq.Request, keys ...tq.ContextKey)
	Next(tq.Handler) tq.Handler
}

// ctxLogger is a middleware handler that logs responses from the server
type ctxLogger struct {
	loggerProvider
	ctx  context.Context
	next tq.Handler
}

// newPacketLogger is a logger scoped to a AAA handler's lifetime
func newPacketLogger(l loggerProvider) *ctxLogger {
	return &ctxLogger{loggerProvider: l}
}

// Next takes in a tq.Handler and returns another one
// This method allows ctxLogger to act as a middleware handler
// by intercepting a call to the next handler, performs operations
// such as overwriting the response ctx, and call the next handler
func (cl *ctxLogger) Next(next tq.Handler) tq.Handler {
	cl.next = next
	return cl
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

// Handle is a middleware handler function, for contextLogging.
// It overwrites the response's context with the ctxLogger's context,
// and calls the Handler specified with Next
// you MUST call Next before calling Handle
func (cl *ctxLogger) Handle(response tq.Response, request tq.Request) {
	response.Context(cl.ctx)
	cl.next.Handle(response, request)
}
