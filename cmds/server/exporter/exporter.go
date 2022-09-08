/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package exporter

import (
	"flag"
	"log"
	"net/http"
	_ "net/http/pprof"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	promExportAddress = flag.String("metrics-address", ":8080", "port for promhttp exporter to listen on")
	exportPromHTTP    = flag.Bool("export-promhttp", true, "execute promHttp handler")
)

// StartPromHTTP will start the prometheus http service that reports our metrics
func StartPromHTTP() error {
	if *exportPromHTTP {
		http.Handle("/metrics", promhttp.Handler())
		log.Printf("starting prometheus http exporter, listening [%v]/metrics", *promExportAddress)
		return http.ListenAndServe(*promExportAddress, nil)
	}
	return nil
}
