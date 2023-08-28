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

// NewAuthenticateStart ...
func NewAuthenticateStart(l loggerProvider, c configProvider) *AuthenticateStart {
	return &AuthenticateStart{loggerProvider: l, configProvider: c, recorderWriter: newPacketLogger(l)}
}

// AuthenticateStart is the main entry point for incoming authenstart packets
type AuthenticateStart struct {
	loggerProvider
	configProvider
	recorderWriter
}

// authenActionStart is a function map that determines which authenticate handler to call given
// the constraints per the rfc when examining action, type and minor version.
type authenActionStart struct {
	action       tq.AuthenAction
	atype        tq.AuthenType
	service      tq.AuthenService
	minorVersion uint8
}

// Handle ...
func (a *AuthenticateStart) Handle(response tq.Response, request tq.Request) {
	var body tq.AuthenStart
	if err := tq.Unmarshal(request.Body, &body); err != nil {
		authenStartHandleUnexpectedPacket.Inc()
		authenStartHandleError.Inc()
		response.ReplyWithContext(
			request.Context,
			tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusError),
				tq.SetAuthenReplyServerMsg(fmt.Sprintf("expected authenticate start packet for sessionID [%v]", request.Header.SessionID)),
			),
			a.recorderWriter,
		)
		return
	}

	authenRouter := map[authenActionStart]tq.Handler{
		// 5.4.2.6.  Enable Requests
		{action: tq.AuthenActionLogin, service: tq.AuthenServiceEnable, minorVersion: tq.MinorVersionOne}: NewAuthenticateASCII(a.loggerProvider, a.configProvider, string(body.User)),
		// 5.4.2.1.  ASCII Login Requests
		{action: tq.AuthenActionLogin, atype: tq.AuthenTypeASCII, minorVersion: tq.MinorVersionDefault}: NewAuthenticateASCII(a.loggerProvider, a.configProvider, string(body.User)),
		// 5.4.2.2.  PAP Login Requests
		{action: tq.AuthenActionLogin, atype: tq.AuthenTypePAP, minorVersion: tq.MinorVersionOne}:      NewAuthenticatePAP(a.loggerProvider, a.configProvider),
		{action: tq.AuthenActionLogin, atype: tq.AuthenTypeCHAP, minorVersion: tq.MinorVersionOne}:     nil, //AuthenCHAPStart not implemented
		{action: tq.AuthenActionLogin, atype: tq.AuthenTypeMSCHAP, minorVersion: tq.MinorVersionOne}:   nil, //AuthenMSCHAPStart not implemented
		{action: tq.AuthenActionLogin, atype: tq.AuthenTypeMSCHAPV2, minorVersion: tq.MinorVersionOne}: nil, //AuthenMSCHAPV2Start not implemented
	}
	key := authenActionStart{action: body.Action, atype: body.Type, minorVersion: request.Header.Version.MinorVersion}
	if h := authenRouter[key]; h != nil {
		h.Handle(response, request)
		return
	}
	// we don't know what this packet is, so we log everything in it. this could log passwords but w/o knowing what this
	// packet was, we can't effectively omit fields, so we guess.  user-msg may contain a password.
	a.Record(request.Context, request.Fields(tq.ContextConnRemoteAddr, tq.ContextConnLocalAddr), "user-msg")
	authenStartHandleUnexpectedPacket.Inc()
	authenStartHandleError.Inc()
	response.ReplyWithContext(
		request.Context,
		tq.NewAuthenReply(
			tq.SetAuthenReplyStatus(tq.AuthenStatusError),
			tq.SetAuthenReplyServerMsg("unknown authenticate start packet type"),
		),
		a.recorderWriter,
	)
}
