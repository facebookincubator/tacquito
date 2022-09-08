/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package dns

import (
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// gauges and counters
	dnsGetMatch = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "secret_provider_dns_get_match",
		Help:      "number of dns secret provider matches",
	})
	dnsError = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: "tacquito",
		Name:      "secret_provider_dns_get_error",
		Help:      "the number of errors encountered when resolving dns",
	})
	// durations
	dnsDurations = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Namespace:  "tacquito",
			Name:       "secret_provider_dns_query_duration_milliseconds",
			Help:       "the time it takes for dns queries to respond, in milliseconds",
			Objectives: map[float64]float64{0.5: 0.05, 0.9: 0.01, 0.99: 0.001},
		},
	)
)

func init() {
	// gauges and counters
	prometheus.MustRegister(dnsGetMatch)
	prometheus.MustRegister(dnsError)
	// durations
	prometheus.MustRegister(dnsDurations)
}
