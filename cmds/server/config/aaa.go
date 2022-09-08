/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package config

import (
	tq "github.com/facebookincubator/tacquito"
)

// loggerProvider provides the logging implementation
type loggerProvider interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
}

// AAAOption ...
type AAAOption func(a *AAA)

// SetAAALogger sets the logging backend
func SetAAALogger(l loggerProvider) AAAOption {
	return func(a *AAA) {
		a.loggerProvider = l
	}
}

// SetAAAUser creats a scoped config for user
func SetAAAUser(u User) AAAOption {
	return func(a *AAA) {
		a.User = u
	}
}

// SetAAAAuthenticator sets the authenticator
func SetAAAAuthenticator(h tq.Handler) AAAOption {
	return func(a *AAA) {
		a.Authenticate = h
	}
}

// SetAAAAuthorizer sets the authorizer
func SetAAAAuthorizer(h tq.Handler) AAAOption {
	return func(a *AAA) {
		a.Authorizer = h
	}
}

// SetAAAAccounter sets the accounter
func SetAAAAccounter(h tq.Handler) AAAOption {
	return func(a *AAA) {
		a.Accounting = h
	}
}

// NewAAA creates a user scope aaa handler grouping
func NewAAA(opts ...AAAOption) *AAA {
	a := &AAA{
		Authenticate: &defaultAuthenticator{},
		Authorizer:   &defaultAuthorizer{},
		Accounting:   &defaultAccounter{},
	}

	for _, opt := range opts {
		opt(a)
	}
	return a
}

// AAA is a user level aaa handler grouping that will provide default behaviors
// for each user if the corresponding A is not injected during loader runs
type AAA struct {
	User
	loggerProvider
	Authenticate tq.Handler
	Authorizer   tq.Handler
	Accounting   tq.Handler
}

type defaultAuthenticator struct{}

// Authenticate default deny implementation
func (a *defaultAuthenticator) Handle(response tq.Response, request tq.Request) {
	response.Reply(
		tq.NewAuthenReply(
			tq.SetAuthenReplyStatus(tq.AuthenStatusFail),
			tq.SetAuthenReplyServerMsg("authentication denied"),
		),
	)
}

type defaultAuthorizer struct{}

// Authorize default deny implementation
func (a *defaultAuthorizer) Handle(response tq.Response, request tq.Request) {
	response.Reply(
		tq.NewAuthorReply(
			tq.SetAuthorReplyStatus(tq.AuthorStatusFail),
			tq.SetAuthorReplyServerMsg("authorization denied"),
		),
	)
}

type defaultAccounter struct{}

// Accounting default deny implementation
func (a *defaultAccounter) Handle(response tq.Response, request tq.Request) {
	response.Reply(
		tq.NewAcctReply(
			tq.SetAcctReplyStatus(tq.AcctReplyStatusError),
			tq.SetAcctReplyServerMsg("accounting denied"),
		),
	)
}
