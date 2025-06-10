/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package loader

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	secretKnown = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_get_secret_known",
		Help:      "number of known secret providers in loader.get calls",
	})
	secretUnknown = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_get_secret_unknown",
		Help:      "number of unknown secret providers in loader.get calls",
	})
	scope = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_build_scope",
		Help:      "number of scopes processed",
	})
	userScopeDuplicate = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_build_user_scope_duplicate",
		Help:      "number of duplicate user scopes encountered",
	})
	userAuthorizerUnassigned = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_build_user_authorizer_unassigned",
		Help:      "number of user with unassigned authorizers",
	})
	userAuthorizerBadConfigRef = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_build_user_authorizer_bad_configref",
		Help:      "number of user with bad config ref authorizer",
	})
	userAuthenticatorUnassigned = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_build_user_authenticator_unassigned",
		Help:      "number of user with unassigned authenticators",
	})
	userAuthenticatorBadConfigRef = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_build_user_authenticator_bad_configref",
		Help:      "number of user with bad config ref authenticators",
	})
	userAccounterUnassigned = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_build_user_accounter_unassigned",
		Help:      "number of user with unassigned accounters",
	})
	userAccounterBadConfigRef = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_build_user_accounter_bad_configref_error",
		Help:      "number of user with bad config ref accounters",
	})
	userTotal = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_build_user_total",
		Help:      "number of users processed in a cycle",
	})
	userScopeUnassigned = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_build_user_scope_unassigned",
		Help:      "number of user scopes unassigned",
	})
	secretProviderMissing = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_build_secret_provider_missing",
		Help:      "number of missing secret providers",
	})
	providerFactoryMissing = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_build_user_provider_factory_missing",
		Help:      "number of missing user provider factory",
	})
	secretProviderGet = prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "tacquito",
		Name:      "loader_build_secret_provider_get",
		Help:      "number of active secret provider queries",
	})
	buildUpdate = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_update_build",
		Help:      "number of builds on config updates",
	})
	buildGet = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_update_get",
		Help:      "number of config get calls from updates",
	})
	userOverrideAuthenticator = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_loader_reduceAuthenticatorAccounterFromGroups_user_override_authenticator",
		Help:      "number of user overrides for authenticator",
	})
	userOverrideAccounter = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "loader_loader_reduceAuthenticatorAccounterFromGroups_user_override_accounter",
		Help:      "number of user overrides for accounter",
	})
	prefixFilterAllowed = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "prefixFilter_allowed",
		Help:      "when prefixFilter allows a remote net.Addr, this is incremented",
	})
	prefixFilterDenied = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "prefixFilter_denied",
		Help:      "when prefixFilter denies a remote net.Addr, this is incremented",
	})

	// Durations
	buildDuration = prometheus.NewSummary(prometheus.SummaryOpts{
		Namespace:  "tacquito",
		Name:       "loader_build_duration",
		Help:       "duration of a successful config build in milliseconds",
		Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
	})
)

func init() {
	prometheus.MustRegister(secretKnown)
	prometheus.MustRegister(secretUnknown)
	prometheus.MustRegister(scope)
	prometheus.MustRegister(userScopeDuplicate)
	prometheus.MustRegister(userAuthorizerUnassigned)
	prometheus.MustRegister(userAuthorizerBadConfigRef)
	prometheus.MustRegister(userAuthenticatorUnassigned)
	prometheus.MustRegister(userAuthenticatorBadConfigRef)
	prometheus.MustRegister(userAccounterUnassigned)
	prometheus.MustRegister(userAccounterBadConfigRef)
	prometheus.MustRegister(userTotal)
	prometheus.MustRegister(userScopeUnassigned)
	prometheus.MustRegister(secretProviderMissing)
	prometheus.MustRegister(providerFactoryMissing)
	prometheus.MustRegister(secretProviderGet)
	prometheus.MustRegister(buildUpdate)
	prometheus.MustRegister(buildGet)
	prometheus.MustRegister(userOverrideAuthenticator)
	prometheus.MustRegister(userOverrideAccounter)
	prometheus.MustRegister(prefixFilterAllowed)
	prometheus.MustRegister(prefixFilterDenied)

	// Durations
	prometheus.MustRegister(buildDuration)
}
