/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package secret

import (
	"context"
	"github.com/facebookincubator/tacquito/cmds/server/config"
)

// New keychain that provides the password via keychain.Key as pre-shared key to use in client calls for
// tacacs obfuscation ops
func New() *Keychain {
	return &Keychain{}
}

// Keychain is a default, unsafe pre-shared key provider
type Keychain struct{}

// Add returns the pre-shared tacacs key to be used with a connection
func (k Keychain) Add(kc config.Keychain) func(context.Context, string) ([]byte, error) {
	// This is an example implementation only.
	// You should provide your own keychain implementation that takes the key and group from keychain
	// and stages this type to return a value from a trusted, secure store.  We short circuit
	// to simply returning a static key as an example
	return func(ctx context.Context, username string) ([]byte, error) {
		return []byte(kc.Key), nil
	}
}
