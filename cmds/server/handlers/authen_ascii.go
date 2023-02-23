/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package handlers

import (
	"fmt"

	tq "github.com/facebookincubator/tacquito"
)

// NewAuthenticateASCII ...
func NewAuthenticateASCII(l loggerProvider, c configProvider, username string) *AuthenticateASCII {
	return &AuthenticateASCII{loggerProvider: l, configProvider: c, username: username}
}

// AuthenticateASCII is the main entry for ascii flows.  the ascii flows are quite complex compared to some of the
// other onese.  This is due to the multiple packet exchanges, its relation to enable level operations and also
// that it may be terminated by a magic bit at anytime (TAC_PLUS_CONTINUE_FLAG_ABORT)
type AuthenticateASCII struct {
	loggerProvider
	configProvider
	username string
}

// Handle is the main entry for ascii flows.
func (a *AuthenticateASCII) Handle(response tq.Response, request tq.Request) {
	if reply := a.authenticateContinueStop(request); reply != nil {
		a.Record(request.Context, request.Fields(tq.ContextConnRemoteAddr))
		response.Reply(reply)
		return
	}
	if a.username == "" {
		// client didn't send us a username to start with
		authenASCIIHandleNeedUsername.Inc()
		a.Record(request.Context, request.Fields(tq.ContextConnRemoteAddr))
		response.Next(NewCtxLogger(a.loggerProvider, request, tq.HandlerFunc(a.getUsername)))
		response.Reply(
			tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusGetUser),
				tq.SetAuthenReplyServerMsg("username:"),
			),
		)
		return
	}
	// clients can provide a user up front, we must look before we can decide what to do next
	a.getUsername(response, request)
}

// getUsername collects a username
func (a *AuthenticateASCII) getUsername(response tq.Response, request tq.Request) {
	// user-msg may contain a password but if we land here, it technically should be a username
	// this should be safe to log without obscure
	defer a.Record(request.Context, request.Fields(tq.ContextConnRemoteAddr))
	if reply := a.authenticateContinueStop(request); reply != nil {
		response.Reply(reply)
		return
	}
	if a.username == "" {
		var body tq.AuthenContinue
		if err := tq.Unmarshal(request.Body, &body); err != nil {
			authenASCIIGetUsernameUnexpectedPacket.Inc()
			authenASCIIGetUsernameAuthenError.Inc()
			response.Reply(
				tq.NewAuthenReply(
					tq.SetAuthenReplyStatus(tq.AuthenStatusError),
					tq.SetAuthenReplyServerMsg("expected authenticate continue packet for AuthenStatusGetUser"),
				),
			)
			return
		}
		// missing username
		if len(body.UserMessage) == 0 {
			authenASCIIGetUsernameAuthenError.Inc()
			authenASCIIGetUsernameMissingUsername.Inc()
			response.Reply(
				tq.NewAuthenReply(
					tq.SetAuthenReplyStatus(tq.AuthenStatusError),
					tq.SetAuthenReplyServerMsg("missing UserMessage, containing the username"),
				),
			)
			return
		}
		a.username = string(body.UserMessage)
	}
	response.Next(NewCtxLogger(a.loggerProvider, request, tq.HandlerFunc(a.getPassword)))
	response.Reply(
		tq.NewAuthenReply(
			tq.SetAuthenReplyStatus(tq.AuthenStatusGetPass),
			tq.SetAuthenReplyServerMsg("password:"),
			tq.SetAuthenReplyFlag(tq.AuthenReplyFlagNoEcho),
		),
	)
}

// getPassword collects a password
func (a *AuthenticateASCII) getPassword(response tq.Response, request tq.Request) {
	// user-msg will contain a password here, obscure it
	defer a.Record(request.Context, request.Fields(tq.ContextConnRemoteAddr), "user-msg")
	if reply := a.authenticateContinueStop(request); reply != nil {
		response.Reply(reply)
		return
	}
	var body tq.AuthenContinue
	if err := tq.Unmarshal(request.Body, &body); err != nil {
		authenASCIIGetPasswordUnexpectedPacket.Inc()
		authenASCIIGetPasswordAuthenError.Inc()
		response.Reply(
			tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusError),
				tq.SetAuthenReplyServerMsg("expected authenticate continue packet for AuthenStatusGetPass"),
			),
		)
		return
	}
	// missing password, don't query backend for user
	if len(body.UserMessage) == 0 {
		authenASCIIGetPasswordMissingPassword.Inc()
		authenASCIIGetPasswordAuthenError.Inc()
		// send a message that doesn't say if the username or password was bad. we do this
		// so as not to signal if the username or the password was bad. no clues as to how
		// to attack this service more effectively.
		response.Reply(
			tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusError),
				tq.SetAuthenReplyServerMsg("unknown username or password"),
			),
		)
		return
	}
	c := a.GetUser(a.username)
	if c == nil {
		a.Debugf(request.Context, "[%v] user [%v] does not have an authenticator associated", request.Header.SessionID, a.username)
		authenASCIIGetPasswordAuthenFail.Inc()
		response.Reply(
			tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusFail),
				tq.SetAuthenReplyServerMsg(fmt.Sprintf("authentication denied [%s]", a.username)),
			),
		)
		return
	}
	c.Authenticate.Handle(response, request)
}

// AuthenticateContinueStop looks for flags in the client request to see if we should terminate.
// The rfc stipulates that this may come at anytime.
// https://datatracker.ietf.org/doc/html/rfc8907#section-5.4.3
func (a *AuthenticateASCII) authenticateContinueStop(request tq.Request) *tq.AuthenReply {
	var body tq.AuthenContinue
	if err := tq.Unmarshal(request.Body, &body); err != nil {
		// not a continue packet, ignore processing here only, later processing still applies
		return nil
	}
	if body.Flags.Has(tq.AuthenContinueFlagAbort) {
		authenASCIIContinueStop.Inc()
		return tq.NewAuthenReply(
			tq.SetAuthenReplyStatus(tq.AuthenStatusFail),
			tq.SetAuthenReplyServerMsg("ending per client request flag AuthenContinueFlagAbort"),
		)
	}
	return nil
}
