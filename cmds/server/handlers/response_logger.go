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
	// TODO make context available here for FieldsWithContext(tq.ContextConnRemoteAddr)
	request := tq.Request{Header: *packet.Header, Body: packet.Body[:]}
	l.Record(l.ctx, request.Fields())
	return 0, nil
}

// Handle implements a middleware logger for next
func (l *ResponseLogger) Handle(response tq.Response, request tq.Request) {
	response.RegisterWriter(l)
	l.next.Handle(response, request)
}
