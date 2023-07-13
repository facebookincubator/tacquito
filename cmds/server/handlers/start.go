/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package handlers

import (
	"context"
	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"
)

// NewStart ...
func NewStart(l loggerProvider) *Start {
	return &Start{loggerProvider: l}
}

// Start is the main entry point for incoming aaa messages from clients.
type Start struct {
	loggerProvider
	configProvider
	options map[string]string
}

// New creates a new start handler.
func (s *Start) New(ctx context.Context, c config.Provider, options map[string]string) tq.Handler {
	return NewResponseLogger(ctx, s.loggerProvider, &Start{loggerProvider: s.loggerProvider, configProvider: c})
}

// Handle implements the tq handler interface
func (s *Start) Handle(response tq.Response, request tq.Request) {
	switch request.Header.Type {
	case tq.Authenticate:
		startAuthenticate.Inc()
		NewAuthenticateStart(s.loggerProvider, s.configProvider).Handle(response, request)
	case tq.Authorize:
		startAuthorize.Inc()
		s.Record(request.Context, request.Fields(tq.ContextConnRemoteAddr, tq.ContextConnLocalAddr))
		NewAuthorizeRequest(s.loggerProvider, s.configProvider).Handle(response, request)
	case tq.Accounting:
		startAccounting.Inc()
		s.Record(request.Context, request.Fields(tq.ContextConnRemoteAddr, tq.ContextConnLocalAddr))
		NewAccountingRequest(s.loggerProvider, s.configProvider).Handle(response, request)
	}
}
