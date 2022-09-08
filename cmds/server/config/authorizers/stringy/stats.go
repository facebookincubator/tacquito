/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package stringy

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// see https://datatracker.ietf.org/doc/html/rfc8907#section-6.2 for pass add/replace
	stringyHandleAuthorizeAcceptPassReplace = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "stringy_handle_authorize_accept_pass_replace",
		Help:      "number of stringy authorize accept pass replace packets",
	})
	stringyHandleAuthorizeAcceptPassAdd = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "stringy_handle_authorize_accept_pass_add",
		Help:      "number of stringy authorize accept pass add packets",
	})
	stringyHandleAuthorizeFail = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "stringy_handle_authorize_fail",
		Help:      "number of stringy authorize fail packets",
	})
	stringyHandleAuthorizeError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "stringy_handle_authorize_error",
		Help:      "number of stringy authorize error packets",
	})
	stringyHandleUnexpectedPacket = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "stringy_handle_unexpected_packet",
		Help:      "number of stringy handle unexpected packets",
	})
)

func init() {
	prometheus.MustRegister(stringyHandleAuthorizeAcceptPassReplace)
	prometheus.MustRegister(stringyHandleAuthorizeAcceptPassAdd)
	prometheus.MustRegister(stringyHandleAuthorizeFail)
	prometheus.MustRegister(stringyHandleAuthorizeError)
	prometheus.MustRegister(stringyHandleUnexpectedPacket)
}
