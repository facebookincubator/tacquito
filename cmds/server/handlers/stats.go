/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package handlers

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	startAuthenticate = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "start_handle_authenticate",
		Help:      "number of authenticate handlers called",
	})
	startAuthorize = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "start_handle_authorize",
		Help:      "number of authorize handlers called",
	})
	startAccounting = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "start_handle_accounting",
		Help:      "number of accounting handlers called",
	})
	authenStartHandleUnexpectedPacket = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenstart_unexpected_packet",
		Help:      "number of authenstart unexpected packets",
	})
	authenStartHandleError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenstart_handle_error",
		Help:      "number of authenstart errors",
	})
	authenStartHandlePAP = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenstart_handle_pap",
		Help:      "number of authenstart pap flows",
	})
	authenASCIIContinueStop = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_handle_continuestop",
		Help:      "number of authen ascii continuestop packets",
	})
	authenASCIIHandleUnexpectedPacket = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_handle_unexpected_packet",
		Help:      "number of authen ascii unexpected packets",
	})
	authenASCIIHandleAuthenFail = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_handle_authen_fail",
		Help:      "number of authen ascii authen fail packets",
	})
	authenASCIIHandleAuthenError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_handle_authen_error",
		Help:      "number of authen ascii authen error packets",
	})
	authenASCIIHandleNeedUsername = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_handle_need_username",
		Help:      "number of authen ascii packets that require asking for username",
	})
	authenASCIIGetUsernameUnexpectedPacket = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_getUsername_unexpected_packet",
		Help:      "number of authen ascii unexpected packets in getUsername call",
	})
	authenASCIIGetUsernameAuthenFail = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_getUsername_authen_fail",
		Help:      "number of authen ascii authen fail packets",
	})
	authenASCIIGetUsernameAuthenError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_getUsername_authen_error",
		Help:      "number of authen ascii authen error packets",
	})
	authenASCIIGetUsernameMissingUsername = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_getUsername_missing_username",
		Help:      "number of authen ascii packets where a username is not in the received packet",
	})
	authenASCIIGetPasswordUnexpectedPacket = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_getPassword_unexpected_packet",
		Help:      "number of authen ascii unexpected packets in the getPassword call",
	})
	authenASCIIGetPasswordAuthenFail = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_getPassword_authen_fail",
		Help:      "number of authen ascii authen fail packets",
	})
	authenASCIIGetPasswordAuthenError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_getPassword_authen_error",
		Help:      "number of authen ascii authen error packets",
	})
	authenASCIIGetPasswordMissingPassword = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenascii_getPassword_missing_password_error",
		Help:      "number of authen ascii packets where a password is not in the received packet",
	})
	authenPAPHandleUnexpectedPacket = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenpap_handle_unexpected_packet",
		Help:      "number of authen pap unexpected packets",
	})
	authenPAPHandleAuthenFail = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenpap_handle_authen_fail",
		Help:      "number of authen pap authen fail packets",
	})
	authenPAPHandleAuthenError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenpap_handle_authen_error",
		Help:      "number of authen pap authen error packets",
	})
	authenPAPHandleMissingPassword = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenpap_handle_missing_password_error",
		Help:      "number of authen pap packets where a password is not in the received packet",
	})
	authenPAPHandleMissingUsername = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenpap_handle_missing_username",
		Help:      "number of authen pap packets where a username is not in the received packet",
	})
	authenPAPHandleAuthenticatorNil = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authenpap_handle_authenticator_nil_error",
		Help:      "number of authen pap packets where we dont have an authetnicator for the user",
	})
	authorizerHandleUnexpectedPacket = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authorizerequest_handle_unexpected_packet",
		Help:      "number of authorize unexpected packets",
	})
	authorizerHandleError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authorizerequest_handle_error",
		Help:      "number of authorize error packets",
	})
	authorizerHandleAuthorizerNil = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "authorizerequest_handle_authorizer_nil_error",
		Help:      "number of authorize handlers with nil authorizers for expected user",
	})
	accountingHandleUnexpectedPacket = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "accountingrequest_handle_unexpected_packet",
		Help:      "number of accounting unexpected packets",
	})
	accountingHandleAccounterNil = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "accountingrequest_handle_accounter_nil",
		Help:      "number of accounting handlers with nil authorizers for expected user",
	})
	accountingHandleError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "accountingrequest_handle_accounter_error",
		Help:      "number of accounting error packets",
	})
	spanHandle = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "span_handle",
		Help:      "number of span handle packets",
	})
	spanHandleWriteSuccess = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "span_handle_write_success",
		Help:      "number of span handle write success",
	})
	spanHandleWriteError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "span_handle_write_error",
		Help:      "number of span handle write error",
	})
	spanHandleError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "span_handle_error",
		Help:      "number of span handle errors",
	})

	// durations
	spanDurations = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Namespace:  "tacquito",
			Name:       "span_handle_duration_milliseconds",
			Help:       "the time spent on a given span handle call, in milliseconds",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
	)
)

func init() {
	prometheus.MustRegister(startAuthenticate)
	prometheus.MustRegister(startAuthorize)
	prometheus.MustRegister(startAccounting)
	prometheus.MustRegister(authenStartHandleUnexpectedPacket)
	prometheus.MustRegister(authenStartHandleError)
	prometheus.MustRegister(authenStartHandlePAP)
	prometheus.MustRegister(authenASCIIContinueStop)
	prometheus.MustRegister(authenASCIIHandleUnexpectedPacket)
	prometheus.MustRegister(authenASCIIHandleAuthenFail)
	prometheus.MustRegister(authenASCIIHandleAuthenError)
	prometheus.MustRegister(authenASCIIHandleNeedUsername)
	prometheus.MustRegister(authenASCIIGetUsernameUnexpectedPacket)
	prometheus.MustRegister(authenASCIIGetUsernameAuthenFail)
	prometheus.MustRegister(authenASCIIGetUsernameAuthenError)
	prometheus.MustRegister(authenASCIIGetUsernameMissingUsername)
	prometheus.MustRegister(authenASCIIGetPasswordUnexpectedPacket)
	prometheus.MustRegister(authenASCIIGetPasswordAuthenFail)
	prometheus.MustRegister(authenASCIIGetPasswordAuthenError)
	prometheus.MustRegister(authenASCIIGetPasswordMissingPassword)
	prometheus.MustRegister(authenPAPHandleUnexpectedPacket)
	prometheus.MustRegister(authenPAPHandleAuthenFail)
	prometheus.MustRegister(authenPAPHandleAuthenError)
	prometheus.MustRegister(authenPAPHandleMissingPassword)
	prometheus.MustRegister(authenPAPHandleMissingUsername)
	prometheus.MustRegister(authenPAPHandleAuthenticatorNil)
	prometheus.MustRegister(authorizerHandleAuthorizerNil)
	prometheus.MustRegister(authorizerHandleUnexpectedPacket)
	prometheus.MustRegister(authorizerHandleError)
	prometheus.MustRegister(accountingHandleUnexpectedPacket)
	prometheus.MustRegister(accountingHandleAccounterNil)
	prometheus.MustRegister(accountingHandleError)
	prometheus.MustRegister(spanHandle)
	prometheus.MustRegister(spanHandleError)
	prometheus.MustRegister(spanHandleWriteSuccess)
	prometheus.MustRegister(spanHandleWriteError)
	prometheus.MustRegister(spanDurations)
}
