/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package main provides a utility to create or verify bcrypt strings used by the bcrypt authenticator
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

var (
	mode = flag.String("mode", "", "supported password hashing modes: [bcrypt, verify-bcrypt]")
)

func main() {
	flag.Parse()
	verifyFlags()
	switch *mode {
	case "bcrypt":
		password := getPassword("Enter Password (echo is off): ")
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			fmt.Printf("hash generation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("bcrypt hex value:", hex.EncodeToString(hash))
	case "verify-bcrypt":
		password := getPassword("Enter Password (echo is off): ")
		hexpw := getPassword("Enter hex value (echo is off): ")
		hash, err := hex.DecodeString(hexpw)
		if err != nil {
			fmt.Printf("hash decode from hex failed: %v\n", err)
			os.Exit(1)
		}
		if err := bcrypt.CompareHashAndPassword(hash, []byte(password)); err != nil {
			fmt.Printf("password validation failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("password validation success")
	default:
		fmt.Printf("unknown mode [%v]\n", *mode)
	}
}

func verifyFlags() {
	if *mode == "" {
		fmt.Println("supported password hashing modes: [bcrypt, verify-bcrypt], please provide one")
		os.Exit(1)
	}
}

func getPassword(msg string) string {
	fmt.Println(msg)
	raw, err := term.ReadPassword(0)
	if err != nil {
		fmt.Println("unable to read input")
		os.Exit(1)
	}
	return string(raw)
}
