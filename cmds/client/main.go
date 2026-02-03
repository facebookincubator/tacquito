/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package main provides a basic tacacs test client for use with tacacs servers and tacquito
package main

import (
	"flag"
	"fmt"
	"os"

	tq "github.com/facebookincubator/tacquito"

	"golang.org/x/term"
)

var (
	username   = flag.String("username", "", "the username to use when authenticating.")
	password   = flag.String("password", "", "the password to use when authenticating.")
	privLvl    = flag.Int("priv-lvl", 1, "the priv lvl that the client is requesting to auth with.")
	network    = flag.String("network", "tcp6", "listen on tcp or tcp6")
	address    = flag.String("address", ":2046", "listen on the provided address:port")
	port       = flag.String("port", "", "the port the client is sourced from, tty0 for example.")
	remAddr    = flag.String("rem-addr", "", "the remote address the client is coming from.")
	secret     = flag.String("secret", "fooman", "the tacacs secret to be used.")
	authenMode = flag.String("authen-mode", "pap", "valid choices, [pap ascii]")

	// TLS options
	tlsConfigFile = flag.String("tls-config", "", "path to TLS configuration file in JSON format. When set, the values inside the file this will override all other TLS cmdline flags")
)

func main() {
	flag.Parse()

	verifyFlags()

	var c *tq.Client
	var err error

	if *tlsConfigFile != "" {
		config, err := tq.LoadTLSConfig(*tlsConfigFile)
		if err != nil {
			fmt.Printf("Error loading TLS config file: %v\n", err)
			os.Exit(1)
		}
		// Create TLS configuration
		tlsConfig, tlsErr := tq.GenClientTLSConfig(config)
		if tlsErr != nil {
			fmt.Printf("Error creating TLS config: %v\n", tlsErr)
			os.Exit(1)
		}

		// Create client with TLS support
		c, err = tq.NewClient(tq.SetClientTLSDialer(*network, *address, tlsConfig))
		if err != nil {
			fmt.Printf("Error creating TLS client: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Connected to server using TLS")
	} else {
		// Create standard client
		c, err = tq.NewClient(tq.SetClientDialer(*network, *address, []byte(*secret)))
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
	}
	defer c.Close()

	switch *authenMode {
	case "pap":
		pap(c)
	case "ascii":
		ascii(c)
	default:
		fmt.Printf("%v is an invalid mode", *authenMode)
	}
}

func verifyFlags() {
	if *username == "" {
		fmt.Println("invalid username, please provide one")
		os.Exit(1)
	}
	if *secret == "" {
		fmt.Println("invalid secret, you must provide one")
		os.Exit(1)
	}
}

func getPassword() string {
	if *password != "" {
		return *password
	}
	fmt.Print("Enter Password: ")
	raw, err := term.ReadPassword(0)
	if err != nil {
		fmt.Println("unable to read password")
		os.Exit(1)
	}
	return string(raw)
}
