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

// NewAuthenticatePAP creates a scoped handler for PAP authentication exchanges
func NewAuthenticatePAP(l loggerProvider, c configProvider) *AuthenticatePAP {
	return &AuthenticatePAP{loggerProvider: l, configProvider: c, recorderWriter: newPacketLogger(l)}
}

// AuthenticatePAP is the main entry for pap authenticate exchanges
type AuthenticatePAP struct {
	loggerProvider
	configProvider
	recorderWriter
	username string
}

// Handle requires that the username and password be present in a AuthenStart packet.
func (a *AuthenticatePAP) Handle(response tq.Response, request tq.Request) {
	authenStartHandlePAP.Inc()
	var body tq.AuthenStart
	if err := tq.Unmarshal(request.Body, &body); err != nil {
		authenPAPHandleUnexpectedPacket.Inc()
		authenASCIIHandleAuthenError.Inc()
		response.ReplyWithContext(
			request.Context,
			tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusError),
				tq.SetAuthenReplyServerMsg("unable to decode authenticate start packet"),
			),
			a.recorderWriter,
		)
		return
	}
	// missing username
	if len(body.User) == 0 {
		a.Debugf(request.Context, "[%v] [%v] username is missing for rem-addr: [%v]", request.Header.SessionID, body.RemAddr)
		authenPAPHandleAuthenError.Inc()
		authenPAPHandleMissingUsername.Inc()
		response.ReplyWithContext(
			request.Context,
			tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusError),
				tq.SetAuthenReplyServerMsg("missing username"),
			),
			a.recorderWriter,
		)
		return
	}
	a.RecordCtx(&request, tq.ContextUser, tq.ContextRemoteAddr, tq.ContextPort, tq.ContextPrivLvl)
	// missing password
	if len(body.Data) == 0 {
		a.Debugf(request.Context, "[%v] [%v] username [%v] is missing a password for rem-addr: [%v]", request.Header.SessionID, body.User, body.RemAddr)
		authenPAPHandleMissingPassword.Inc()
		authenPAPHandleAuthenError.Inc()
		response.ReplyWithContext(
			a.Context(),
			tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusError),
				tq.SetAuthenReplyServerMsg("missing password"),
			),
			a.recorderWriter,
		)
		return
	}
	c := a.GetUser(string(body.User))
	if c == nil {
		a.Debugf(request.Context, "[%v] user [%v] does not have an authenticator associated", request.Header.SessionID, body.User)
		authenPAPHandleAuthenFail.Inc()
		authenPAPHandleAuthenticatorNil.Inc()
		response.ReplyWithContext(
			a.Context(),
			tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusFail),
				tq.SetAuthenReplyServerMsg(fmt.Sprintf("authentication denied [%s]", string(body.User))),
			),
			a.recorderWriter,
		)
		return
	}
	NewResponseLogger(a.Context(), a.loggerProvider, c.Authenticate).Handle(response, request)
}
