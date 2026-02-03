/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package main

import (
	"context"
	"flag"
	"net"
	"os"
	"os/signal"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"
	"github.com/facebookincubator/tacquito/cmds/server/config/accounters/local"
	"github.com/facebookincubator/tacquito/cmds/server/config/authenticators/bcrypt"
	"github.com/facebookincubator/tacquito/cmds/server/config/authorizers/stringy"
	"github.com/facebookincubator/tacquito/cmds/server/log"

	"github.com/facebookincubator/tacquito/cmds/server/config/secret"
	"github.com/facebookincubator/tacquito/cmds/server/config/secret/prefix"
	"github.com/facebookincubator/tacquito/cmds/server/exporter"
	"github.com/facebookincubator/tacquito/cmds/server/handlers"
	"github.com/facebookincubator/tacquito/cmds/server/loader"
	"github.com/facebookincubator/tacquito/cmds/server/loader/fsnotify"
	"github.com/facebookincubator/tacquito/cmds/server/loader/yaml"
)

var (
	network           = flag.String("network", "tcp6", "listen on tcp or tcp6")
	address           = flag.String("address", ":2046", "listen on the provided address:port")
	proxy             = flag.Bool("proxy", false, "proxy enables proxy header processing")
	configPath        = flag.String("config", "tacquito.yaml", "the string path representing the storage location of the server config")
	accountingLogPath = flag.String("acct-log-path", "/tmp/tacquito_accounting.log", "the string path representing the storage location of the server accounting logs")
	level             = flag.Int("level", 30, "log levels; 10 = error, 20 = info, 30 = debug")

	// TLS options
	useTLS               = flag.Bool("tls", false, "enable TLS support as per IETF draft-ietf-opsawg-tacacs-tls13-07")
	tlsCertFile          = flag.String("tls-cert", "", "path to TLS certificate file")
	tlsKeyFile           = flag.String("tls-key", "", "path to TLS key file")
	tlsCAFile            = flag.String("tls-ca", "", "path to TLS CA certificate file for client certificate validation")
	tlsRequireClientCert = flag.Bool("tls-require-client-cert", false, "require client certificates for TLS connections")
)

func main() {
	flag.Parse()
	logger := log.New(*level, os.Stderr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// we need thrift running to collect Prometheus stats for ODS
	go func() {
		defer cancel()
		if err := exporter.StartPromHTTP(); err != nil {
			logger.Errorf(ctx, "failed to start prometheus http exporter: %v", err)
		}
	}()

	accountingLogger, err := local.New(logger, local.SetLogSinkDefault(*accountingLogPath, "tacquito"))
	if err != nil {
		logger.Fatalf(ctx, "error building accounting logger; %v", err)
		return
	}

	shhh := &shh{}
	sp, err := loader.NewLocalConfig(
		ctx,
		*configPath,
		fsnotify.New(ctx, yaml.New(), logger),
		loader.SetLoggerProvider(logger),
		loader.SetKeychainProvider(secret.New()),
		loader.SetConfigProvider(config.New()),
		loader.SetAuthorizerProvider(stringy.New(logger)),
		loader.RegisterSecretProviderType(config.PREFIX, prefix.New(logger)),
		loader.RegisterHandlerType(config.START, handlers.NewStart(logger)),
		loader.RegisterAuthenticator(config.BCRYPT, bcrypt.New(logger, shhh)),
		loader.RegisterAccounter(config.FILE, accountingLogger),
	)
	if err != nil {
		logger.Fatalf(ctx, "error fetching config; %v", err)
		return
	}

	// setup our listener
	var tqListener tq.DeadlineListener

	listener, err := net.Listen(*network, *address)
	if err != nil {
		logger.Fatalf(ctx, "error reading address: %v", err)
		return
	}

	// Create server with options
	serverOpts := []tq.Option{tq.SetUseProxy(*proxy)}

	if *useTLS {
		// If TLS is enabled but no certificate/key files are provided, log error an exit
		config, err := tq.GenTLSConfig(*tlsCertFile, *tlsKeyFile, *tlsCAFile, *tlsRequireClientCert)
		if err != nil {
			logger.Errorf(ctx, "error generating tls config: %v", err)
			return
		}
		tlsListen, err := tq.NewTLSListener(listener, config)
		if err != nil {
			logger.Errorf(ctx, "error creating tls listener: %v", err)
			return
		}
		tqListener = tlsListen
		serverOpts = append(serverOpts, tq.SetUseTLS(true))
	} else {
		tcpListener, ok := listener.(*net.TCPListener)
		if !ok {
			logger.Errorf(ctx, "listener must be a tcp based listener")
			return
		}
		tqListener = tcpListener
		logger.Infof(ctx, "serve on %v", tcpListener.Addr().String())
	}

	s := tq.NewServer(logger, sp, serverOpts...)
	if err := s.Serve(ctx, tqListener); err != nil {
		logger.Errorf(ctx, "error listening: %v", err)
		return
	}
}
