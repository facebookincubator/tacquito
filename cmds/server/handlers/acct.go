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

// NewAccountingRequest ...
func NewAccountingRequest(l loggerProvider, c configProvider) *AccountingRequest {
	return &AccountingRequest{loggerProvider: l, configProvider: c, recorderWriter: newPacketLogger(l)}
}

// AccountingRequest is the main entry point for incoming AcctRequest packets
type AccountingRequest struct {
	loggerProvider
	configProvider
	recorderWriter
}

// Handle ...
func (a *AccountingRequest) Handle(response tq.Response, request tq.Request) {
	var body tq.AcctRequest
	if err := tq.Unmarshal(request.Body, &body); err != nil {
		a.Errorf(request.Context, "unable to unmarshal accounting packet : %v", err)
		accountingHandleUnexpectedPacket.Inc()
		accountingHandleError.Inc()
		response.ReplyWithContext(
			request.Context,
			tq.NewAcctReply(
				tq.SetAcctReplyStatus(tq.AcctReplyStatusError),
				tq.SetAcctReplyServerMsg("expected accounting request packet"),
			),
			a.recorderWriter,
		)
		return
	}

	a.RecordCtx(&request, tq.ContextUser, tq.ContextRemoteAddr, tq.ContextReqArgs, tq.ContextAcctType, tq.ContextPort, tq.ContextPrivLvl, tq.ContextFlags)
	// TODO implement a fallback for cases where a username may not be present.
	c := a.GetUser(string(body.User))
	if c == nil {
		a.Debugf(request.Context, "[%v] user [%v] does not have an accounter associated", request.Header.SessionID, body.User)
		accountingHandleAccounterNil.Inc()
		response.ReplyWithContext(
			a.Context(),
			tq.NewAcctReply(
				tq.SetAcctReplyStatus(tq.AcctReplyStatusError),
				// ensure user field is present in accounting packet, it could cause this.
				tq.SetAcctReplyServerMsg(fmt.Sprintf("failed to lookup user [%s] for accounting login", string(body.User))),
			),
			a.recorderWriter,
		)
		return
	}

	NewResponseLogger(a.Context(), a.loggerProvider, c.Accounting).Handle(response, request)
}
