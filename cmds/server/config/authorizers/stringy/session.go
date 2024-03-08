/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package stringy implements the only authorizer package available in tacquito.
package stringy

import (
	"context"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"
)

// NewSessionBasedAuthorizer will return a SessionBasedAuthorizer authorizer. If initial request params
// are not suitable for command based, it returns nil
func NewSessionBasedAuthorizer(ctx context.Context, l loggerProvider, b tq.AuthorRequest, u config.User) *SessionBasedAuthorizer {
	return &SessionBasedAuthorizer{ctx: ctx, loggerProvider: l, body: b, user: u}
}

// SessionBasedAuthorizer provides a session based authorizer
//
// session based authorization is one of the more challenging aspects of tacacs+.  Different vendors
// often require or expect values that may be duplicates in terms of the attribute value, such as:
// "shell:roles*admin" and "shell:roles*user".  It's further complicated by the use of = or * which carry
// client side implications about how to process the received response from the server.
//
// Several assumptions are made on session based auth flows.
//  1. AuthorStatusPassAdd is the default response we send.  This often turns to AuthorStatusPassRepl in the
//     event that config specifies an optional avp.
//  2. Config that has no match conditions, but has a service name that matches either the A or P in avp, will
//     get all of their SetValues applied in the response.  It's an implicit match all.  We match on A or P because
//     there are forms where P will be an empty string, EG, shell*.  Here A=shell, V=* and P="".  We also interchange
//     avp with asv in some data structures.  AVP typically means attribute value pairs as read directly from the client
//     or injected by the authorizer.  They are strings which form a []string as args.  ASV are attribute seperator values.
//     These are special types that can disassemble an avp and reassemble it, while providing information about the values.
//  3. Config that has Match values attached to them, those values must all be satisfied for the code to attach any
//     SetValues in the response.
type SessionBasedAuthorizer struct {
	loggerProvider
	ctx  context.Context
	body tq.AuthorRequest
	user config.User
}

// Handle will respond with failures or accepts as needed
func (sa SessionBasedAuthorizer) Handle(response tq.Response, request tq.Request) {
	if args, status := sa.evaluate(); len(args) > 0 {
		sa.Debugf(request.Context, "authorized user [%v] as session based; args %v", sa.user.Name, args)
		switch status {
		case tq.AuthorStatusPassAdd:
			stringyHandleAuthorizeAcceptPassAdd.Inc()
		case tq.AuthorStatusPassRepl:
			stringyHandleAuthorizeAcceptPassReplace.Inc()
		}
		response.Reply(
			tq.NewAuthorReply(
				tq.SetAuthorReplyStatus(status),
				tq.SetAuthorReplyServerMsg("authorization approved"),
				tq.SetAuthorReplyArgs(args...),
			),
		)
		return
	}
	sa.Debugf(request.Context, "user [%v] failed session based authorization", sa.user.Name)
	stringyHandleAuthorizeFail.Inc()
	response.Reply(
		tq.NewAuthorReply(
			tq.SetAuthorReplyStatus(tq.AuthorStatusFail),
			tq.SetAuthorReplyServerMsg("not authorized"),
		),
	)
}

// evaluate is the main entry point for session based auth flows
func (sa SessionBasedAuthorizer) evaluate() ([]string, tq.AuthorStatus) {
	// overload the body.Args fields to include injected arg concepts in them.  Doing so artifically injects avps into the
	// requested client args and allows them to behave in evaluation the same as if they came from the client.  We do this for
	// args that will never present in a client request, but for things we'd like to filter on.  A use cases is filtering for scope
	sa.body.Args = append(sa.body.Args, tq.Arg(sa.user.GetLocalizedScope()))

	args := sa.body.Args.Args()
	responseArgs := make(tq.Args, 0, len(args))
	authorStatus := tq.AuthorStatusPassAdd

	for _, s := range sa.user.Services {
		s.TrimSpace()
		// optional == true means we hit a client delim of * or we encountered it in our own config
		// via Optional = true.
		matched, optional := sa.serviceMatcherModifier(args, s)
		if optional {
			authorStatus = tq.AuthorStatusPassRepl
		}
		responseArgs.Append(matched...)
	}
	return responseArgs.Args(), authorStatus
}

// serviceMatcherModifier matches incoming attribute value pairs from the client against our config
func (sa SessionBasedAuthorizer) serviceMatcherModifier(args []string, c config.Service) ([]string, bool) {
	avps := make([]string, 0, len(c.SetValues))
	collateAVPs := func(s ...config.Service) ([]string, bool) {
		// optional here represents `*` per the rfc
		optional := false
		unfiltered := make([]string, 0, len(c.SetValues))
		for _, v := range c.SetValues {
			if v.Optional {
				// detected an optional
				optional = true
			}
			unfiltered = append(unfiltered, v.String())
		}
		return unfiltered, optional
	}

	// Optional arguments are ones that may be disregarded by either
	// client or server.  Mandatory arguments require that the receiving
	// side can handle the argument, that is, its implementation and
	// configuration includes the details of how to act on it.  If the
	// client receives a mandatory argument that it cannot handle, it
	// MUST consider the authorization to have failed.  The value part of
	// an argument-value pair may be empty, that is, the length of the
	// value may be zero.

	// optional here represents `*` per the rfc
	optional := false
	for _, avp := range args {
		a, s, v := tq.Arg(avp).ASV()
		// attempt to match config names to avp names
		if a != c.Name && v != c.Name {
			continue
		}
		// we do not count cmd* as an indicator of optional
		// which ultimately influences our AuthorStatus code
		if a != "cmd" && s == "*" {
			// detected an optional
			optional = true
		}
		// No match conditions mean we apply the values strictly based on the service=shell in the args
		// we dedupe in a higher call, but no additional changes are made.  A vast majority of config
		// can easily be built this way, but will often result in sending too many arguments back to
		// the client.  The use of the optional setting for values becomes very important in this circumstance
		if len(c.Match) == 0 {
			unfiltered, isOptional := collateAVPs(c)
			if isOptional {
				optional = true
			}
			avps = append(avps, unfiltered...)
			continue
		}
		// if serviceMatcher is used, then we have match conditions we must evaluate.  These conditions exist
		// within the args that the client sent to us or args that this handler may have injected.  We may send
		// back more args that what they asked, as in scenarios where cmd= or cmd* is requested.
		if sa.serviceMatcher(args, c.Match) {
			unfiltered, isOptional := collateAVPs(c)
			if isOptional {
				optional = true
			}
			avps = append(avps, unfiltered...)
		}
	}
	return avps, optional
}

// serviceMatcher will evaluate the args sent in a request to see if any matches exist with
// a Service type attached to the user.  This func simply identifies if we match on the conditions
// provided.
func (sa SessionBasedAuthorizer) serviceMatcher(args []string, matchers []config.Value) bool {
	kvs := map[string]string{}
	for _, arg := range args {
		a, _, v := tq.Arg(arg).ASV()
		kvs[a] = v
	}
	for len(matchers) > 0 {
		var m config.Value
		m, matchers = matchers[0], matchers[1:]
		argV, ok := kvs[m.Name]
		if !ok {
			return false
		}
		for _, v := range m.Values {
			if argV != v {
				return false
			}
		}
	}
	// this is true if len(m.Match)== 0 OR we looped over all match conditions and they were true
	return true
}
