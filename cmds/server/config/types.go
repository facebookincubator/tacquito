/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package config

import (
	"fmt"
	"strings"
)

// Action ...
type Action int

// AuthenticatorType ...
type AuthenticatorType int

// AccounterType ...
type AccounterType int

var (
	// DENY is for Cmd actions
	DENY Action = 1
	// PERMIT is for Cmd actions
	PERMIT Action = 2

	// BCRYPT is for Authenticators
	BCRYPT AuthenticatorType = 1

	// SHA512 is for Authenticators
	SHA512 AuthenticatorType = 2

	// STDERR is for Logger
	STDERR AccounterType = 1
	// SYSLOG is for Logger
	SYSLOG AccounterType = 2
	// FILE is for writng logs to local files
	FILE AccounterType = 3
)

// User is a fully composed version of all settings a user needs to go through aaa.  All items on the
// user level will overwrite any settings provided by any inherited groups.  Explicit settings on the
// user should be considered an override of any group level setting.
type User struct {
	Name          string         `yaml:"name" json:"name"`
	Scopes        []string       `yaml:"scopes,omitempty" json:"scopes,omitempty"`
	Groups        []Group        `yaml:"groups,omitempty" json:"groups,omitempty"`
	Services      []Service      `yaml:"services,omitempty" json:"services,omitempty"`
	Commands      []Command      `yaml:"commands,omitempty" json:"commands,omitempty"`
	Authenticator *Authenticator `yaml:"authenticator,omitempty" json:"authenticator,omitempty"`
	Accounter     *Accounter     `yaml:"accounter,omitempty" json:"accounter,omitempty"`
}

// HasScope returns bool if scope is found to be bound to this user
func (u User) HasScope(scope string) bool {
	for _, s := range u.Scopes {
		if scope == s {
			return true
		}
	}
	return false
}

// LocalizeToScope will set the Scopes field to the supplied scope name
// no validation is done and the string is accepted as is.
func (u *User) LocalizeToScope(scope string) {
	u.Scopes = []string{scope}
}

// GetLocalizedScope will return the singular scope that this user has been localized to
// if localization has not yet been performed, we use the first value, if available
func (u User) GetLocalizedScope() string {
	if len(u.Scopes) >= 1 {
		// return in the form of an avp string
		return fmt.Sprintf("scope=%s", u.Scopes[0])
	}
	// shouldn't ever happen except in incomplete unit test setups
	return "scope=no-scope-set"
}

// Group represents a set of services, commands, authenticators and a logger.
// groups do not inherit other groups.  All other options will be unique items,
// not duplicated within a given group.  These items are merged into a user level
// configuration, with user level items taking precedence over any group setting.
type Group struct {
	Name          string         `yaml:"name" json:"name"`
	Services      []Service      `yaml:"services,omitempty" json:"services,omitempty"`
	Commands      []Command      `yaml:"commands,omitempty" json:"commands,omitempty"`
	Authenticator *Authenticator `yaml:"authenticator,omitempty" json:"authenticator,omitempty"`
	Accounter     *Accounter     `yaml:"accounter,omitempty" json:"accounter,omitempty"`
	Comment       string         `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// Service represents a concept that looks for tacplus attributes, matches them and sets/replaces
// client provided attribute pairs.  Example:
//
//	Service{
//		Name: "junos-exec",
//		SetValues: []Value{
//			{Name: "allow-commands", Values: []string{"^configure (private|exclusive)$"},
//			{Name: "deny-commands", Values: []string{"(^configure$)|(^configure (batch|dynamic)$)}",
//		},
//	}
//
// Is the same as the tacplus config would express it:
//
//	service = junos-exec {
//		local-user-name = netops
//		allow-commands = "^configure (private|exclusive)$"
//		deny-commands = "(^configure$)|(^configure (batch|dynamic)$)"
//	}
//
// Another example of matching and setting attribute values pairs:
//
//	Service{
//		Name: "ppp",
//	 Match: []Value{
//	   {NameL: "protocol", Values: []string{"ip"},
//	},
//
//		SetValues: []Value{
//			{Name: "F5-LTM-User-Console", Values: []string{"1"}},
//			{Name: "F5-LTM-User-Partition": Values []string{"all"}},
//		},
//	}
//
// but in tacplus world as:
//
//	service = ppp protocol = ip {
//		F5-LTM-User-Info-1 = netops
//		F5-LTM-User-Console = 1
//		F5-LTM-User-Role = 0
//		F5-LTM-User-Partition = All
//	}
type Service struct {
	Name      string  `yaml:"name" json:"name"`
	Match     []Value `yaml:"match,omitempty" json:"match,omitempty"`
	SetValues []Value `yaml:"set_values,omitempty" json:"set_values,omitempty"`
	Optional  bool    `yaml:"is_optional" json:"is_optional"`
	Comment   string  `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// TrimSpace removes all leading and trailing white space removed, as defined by Unicode.
func (s *Service) TrimSpace() {
	s.Name = strings.TrimSpace(s.Name)
}

// Value is used within services
type Value struct {
	Name     string   `yaml:"name" json:"name"`
	Values   []string `yaml:"values,omitempty" json:"values,omitempty"`
	Optional bool     `yaml:"is_optional" json:"is_optional"`
	Comment  string   `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// TrimSpace removes all leading and trailing white space removed, as defined by Unicode.
func (v *Value) TrimSpace() {
	v.Name = strings.TrimSpace(v.Name)
	for i, m := range v.Values {
		v.Values[i] = strings.TrimSpace(m)
	}
}

func (v *Value) String() string {
	var sep string
	switch v.Optional {
	case true:
		sep = "*"
	default:
		sep = "="
	}
	return fmt.Sprintf("%v%v%v", v.Name, sep, strings.Join(v.Values, " "))
}

// Command represents a command and args/pattern to authorize a user's actions
// Example:
//
//	Command{
//		Name:"|",
//		Match: []string{
//			"grep.*",
//			"tail.*",
//		},
//		Action: Permit,
//	}
//
// Is the same as the tacplus config would express it:
//
//	cmd = | {
//		permit grep.*
//		permit tail.*
//	}
type Command struct {
	Name    string   `yaml:"name" json:"name"`
	Match   []string `yaml:"match,omitempty" json:"match,omitempty"`
	Action  Action   `yaml:"action" json:"action"`
	Comment string   `yaml:"comment,omitempty" json:"comment,omitempty"`
}

// TrimSpace removes all leading and trailing white space removed, as defined by Unicode.
func (c *Command) TrimSpace() {
	c.Name = strings.TrimSpace(c.Name)
	for i, m := range c.Match {
		c.Match[i] = strings.TrimSpace(m)
	}
}

// Authenticator represents the authenticator backend that is responsible for password validation.
type Authenticator struct {
	Type    AuthenticatorType `yaml:"type" json:"type"`
	Options map[string]string `yaml:"options,omitempty" json:"options,omitempty"`
}

// Accounter represents the accounting backend resonsible for logging accounting activities.
type Accounter struct {
	Name    string            `yaml:"name" json:"name"`
	Type    AccounterType     `yaml:"type" json:"type"`
	Options map[string]string `yaml:"options" json:"options"`
}

// ProviderType is associated to a ConfigProvider and indicates what sort of
// selection process is used when identifying what psk and config to provide to
// a calling client
type ProviderType int

// HandlerType is the handler to use for incoming client exchanges.  the standard
// package has one type, START, but you may provide others at your discretion.
type HandlerType int

var (
	// PREFIX matches net.Conn.RemAddr addresses to a SecretConfig
	PREFIX ProviderType = 1
	// DNS matches a hostname that is resolved from net.Conn.RemAddr
	DNS ProviderType = 2

	// START is a handler to use for incoming connections
	START HandlerType = 1
	// SPAN is to be used when you wish to replicate packets of a connection
	// to another host(a development server for example) for inspection/debugging
	SPAN HandlerType = 2
)

// SecretConfig applies to a group of client devices or even to a single one
// depending on how the secret providers are configured
type SecretConfig struct {
	Name    string            `yaml:"name" json:"name"`
	Secret  Keychain          `yaml:"secret" json:"secret"`
	Handler Handler           `yaml:"handler" json:"handler"`
	Type    ProviderType      `yaml:"type" json:"type"`
	Options map[string]string `yaml:"options,omitempty" json:"options,omitempty"`
}

// Handler instructs the server what handler to use for the given SecretConfig
type Handler struct {
	Type    HandlerType       `yaml:"type" json:"type"`
	Options map[string]string `yaml:"options,omitempty" json:"options,omitempty"`
}

// Keychain represents a secure storage system whereas you may retrieve your
// sensitive credentials without storing them explicitly in config.
type Keychain struct {
	Group string `yaml:"group" json:"group"`
	Key   string `yaml:"key" json:"key"`
}

// ServerConfig represents a config for the server
type ServerConfig struct {
	Secrets     []SecretConfig `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	Users       []User         `yaml:"users,omitempty" json:"users,omitempty"`
	PrefixDeny  []string       `yaml:"prefix_deny,omitempty" json:"prefix_deny,omitempty"`
	PrefixAllow []string       `yaml:"prefix_allow,omitempty" json:"prefix_allow,omitempty"`
}
