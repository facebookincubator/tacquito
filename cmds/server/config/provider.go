/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package config provides an example implementation of the tacquito.ConfigProvider interface.
package config

// Provider ...
type Provider interface {
	GetUser(user string) *AAA
}

// New returns a tacquito.ConfigProvider that maps a scoped username to a given
// SecretConfig.
func New() AAAProvider {
	return make(map[string]*AAA)
}

// AAAProvider gives us scoped AAA types, which are a wrapped User type
type AAAProvider map[string]*AAA

// New returns a scoped provider for users
func (s AAAProvider) New(users map[string]*AAA) Provider {
	return AAAProvider(users)
}

// GetUser gets the handlers.Config that is associated to a username
func (s AAAProvider) GetUser(username string) *AAA {
	return s[username]
}
