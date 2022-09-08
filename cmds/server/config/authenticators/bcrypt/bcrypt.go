/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package bcrypt implements a tqcquito Config interface.  It uses bcrypt
// to secure the password in a hashed form and stores it statically in source.
// This is strictly an example of how this interface might be implemented.  It is
// not recommended to be used in production and is only an example.
package bcrypt

import (
	"context"
	"encoding/hex"
	"fmt"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config/authenticators"

	"golang.org/x/crypto/bcrypt"
)

// loggerProvider provides the logging implementation
type loggerProvider interface {
	Infof(ctx context.Context, format string, args ...interface{})
	Errorf(ctx context.Context, format string, args ...interface{})
	Record(ctx context.Context, r map[string]string, obscure ...string)
}

// getSecret is the expected behavior for fetching sha hashes from keychain
// types that implement this should be thread safe
type getSecret interface {
	GetSecret(ctx context.Context, name, group string) ([]byte, error)
}

// supportedOptions map will be unmarshaled into this type
//
// hash - if present, we use it blindly until a config change removes it.
// group - the group that holds the key we're looking for
// key - the key in the keychain group. this is may or may not be == username
func newSupportedOptions(username string, options map[string]string) supportedOptions {
	opts := supportedOptions{
		hash:  options["hash"],
		group: options["group"],
		key:   options["key"],
	}
	if opts.key == "" {
		opts.key = username
	}
	return opts
}

type supportedOptions struct {
	// hash - if present, we use it blindly until a config change removes it. Hash is optional.
	hash string
	// group - the group within keychain that holds the key we're looking for. group is optional
	group string
	// key - the key in the group within keychain. this is may or may not be == username
	key string
}

func (s *supportedOptions) setKey(username string) {
	if s.key == "" {
		s.key = username
	}
}

func (s supportedOptions) validate() error {
	if len(s.hash) == 0 && len(s.key) == 0 {
		return fmt.Errorf("missing required option keys for bcrypt authenticator; %v", s)
	}
	return nil
}

// New Bcrypt Authenticator
func New(l loggerProvider, s getSecret) *Authenticator {
	return &Authenticator{loggerProvider: l}
}

// Authenticator with bcrypt password hashing used for validation
type Authenticator struct {
	loggerProvider
	authenticators.Methods
	username string
	supportedOptions

	getSecret
}

// New creates a new bcrypt authenticator which implements tq.Config
func (a Authenticator) New(username string, options map[string]string) (tq.Handler, error) {
	opts := newSupportedOptions(username, options)
	if err := opts.validate(); err != nil {
		return nil, err
	}
	return &Authenticator{loggerProvider: a.loggerProvider, username: username, supportedOptions: opts}, nil
}

// Handle handles all authenticate message types, scoped to the uid
func (a Authenticator) Handle(response tq.Response, request tq.Request) {
	password, err := a.GetPassword(request)
	if err != nil {
		response.Reply(
			tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusError),
				tq.SetAuthenReplyServerMsg(fmt.Sprintf("%v", err)),
			),
		)
		return
	}
	var expectedHash []byte
	if len(a.hash) > 0 {
		// if hash was a key in options, we see that as an override and do not call keychain
		secret, err := hex.DecodeString(a.hash)
		if err != nil {
			a.Errorf(request.Context, "error decoding the hex encoded password for user [%v]; %v", a.username, err)
			response.Reply(
				tq.NewAuthenReply(
					tq.SetAuthenReplyStatus(tq.AuthenStatusFail),
					tq.SetAuthenReplyServerMsg("login failure"),
				),
			)
			return
		}
		expectedHash = secret
	} else {
		secret, err := a.GetSecret(request.Context, a.username, a.group)
		if err != nil {
			a.Errorf(request.Context, "failure in keychain query for user [%v] using a sha512 hashed password; %v", a.username, err)
			response.Reply(
				tq.NewAuthenReply(
					tq.SetAuthenReplyStatus(tq.AuthenStatusFail),
					tq.SetAuthenReplyServerMsg("login failure"),
				),
			)
		}
		expectedHash = secret
	}

	if err := bcrypt.CompareHashAndPassword(expectedHash, []byte(password)); err == nil {
		a.Infof(request.Context, "accepting user [%v] using a bcrypt password", a.username)
		response.Reply(
			tq.NewAuthenReply(
				tq.SetAuthenReplyStatus(tq.AuthenStatusPass),
				tq.SetAuthenReplyServerMsg("login success"),
			),
		)
		return
	}

	a.Errorf(request.Context, "failed to validate the user [%v] using a bcrypt password", a.username)
	response.Reply(
		tq.NewAuthenReply(
			tq.SetAuthenReplyStatus(tq.AuthenStatusFail),
			tq.SetAuthenReplyServerMsg("login failure"),
		),
	)
}
