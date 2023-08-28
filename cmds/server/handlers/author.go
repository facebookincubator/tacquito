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

// NewAuthorizeRequest ...
func NewAuthorizeRequest(l loggerProvider, c configProvider) *AuthorizeRequest {
	return &AuthorizeRequest{loggerProvider: l, configProvider: c, recorderWriter: newPacketLogger(l)}
}

// AuthorizeRequest is the main entry point for incoming AuthorRequest packets
type AuthorizeRequest struct {
	loggerProvider
	configProvider
	recorderWriter
}

// Handle ...
func (a *AuthorizeRequest) Handle(response tq.Response, request tq.Request) {
	var body tq.AuthorRequest
	if err := tq.Unmarshal(request.Body, &body); err != nil {
		a.Debugf(request.Context, "failed to unmarshall AuthorRequest [%v]", err)
		authorizerHandleUnexpectedPacket.Inc()
		authorizerHandleError.Inc()
		response.ReplyWithContext(
			request.Context,
			tq.NewAuthorReply(
				tq.SetAuthorReplyStatus(tq.AuthorStatusError),
				tq.SetAuthorReplyServerMsg("invalid AuthorRequest packet"),
			),
			a.recorderWriter,
		)
		return
	}
	a.RecordCtx(&request, tq.ContextUser, tq.ContextRemoteAddr, tq.ContextReqArgs, tq.ContextPort, tq.ContextPrivLvl)
	c := a.GetUser(string(body.User))
	if c == nil {
		a.Debugf(request.Context, "[%v] user [%v] does not have an authorizer associated", request.Header.SessionID, body.User)
		authorizerHandleAuthorizerNil.Inc()
		response.ReplyWithContext(
			a.Context(),
			tq.NewAuthorReply(
				tq.SetAuthorReplyStatus(tq.AuthorStatusFail),
				tq.SetAuthorReplyServerMsg(
					fmt.Sprintf("authorization denied for user [%s]", string(body.User)),
				),
			),
			a.recorderWriter,
		)
		return
	}
	NewResponseLogger(a.Context(), a.loggerProvider, c.Authorizer).Handle(response, request)
}
