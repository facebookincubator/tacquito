/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package stringy implements the only authorizer package available in tacquito.
package stringy

import (
	"context"
	"regexp"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"
)

const (
	// default anchors for regex expressions embedded in command match attributes
	// stored as bytes and strs for matching and concatenation
	regexStartByte = '^'
	regexEndByte   = '$'
	regexStartStr  = "^"
	regexEndStr    = "$"
)

// NewCommandBasedAuthorizer will return a CommandBasedAuthorizer authorizer. If initial request params
// are not suitable for command based, it returns nil
func NewCommandBasedAuthorizer(ctx context.Context, l loggerProvider, b tq.AuthorRequest, u config.User) *CommandBasedAuthorizer {
	// commands are also only evaluated if service == shell
	if b.Args.Service() != "shell" {
		return nil
	}
	// cmd= and cmd* are not allowed. the command cmd=show etc must be specified
	// cmd*show is also not allowed. Only the madatory separator is considered valid
	a, s, v := b.Args.CommandSplit()
	if a != "cmd" || s != "=" || v == "" {
		return nil
	}
	return &CommandBasedAuthorizer{ctx: ctx, loggerProvider: l, body: b, user: u}
}

// CommandBasedAuthorizer provides a command based authorizer which only work under the following
// scenarios:
//
// cmd=show cmd-arg=system cmd-arg=<cr>
// cmd=show cmd-arg=system
// cmd=show
//
// <cr> is treated as an optional command arg and stripped out when processing the args
// in types.go in the config package
type CommandBasedAuthorizer struct {
	loggerProvider
	ctx  context.Context
	body tq.AuthorRequest
	user config.User
}

// Handle will respond with failures or accepts as needed
func (a CommandBasedAuthorizer) Handle(response tq.Response, request tq.Request) {
	if a.evaluate() {
		a.Debugf(request.Context, "authorized user [%v] as command based", a.user.Name)
		stringyHandleAuthorizeAcceptPassAdd.Inc()
		response.Reply(
			tq.NewAuthorReply(
				tq.SetAuthorReplyStatus(tq.AuthorStatusPassAdd),
			),
		)
		return
	}
	a.Debugf(request.Context, "user [%v] failed command based authorization", a.user.Name)
	stringyHandleAuthorizeFail.Inc()
	response.Reply(
		tq.NewAuthorReply(
			tq.SetAuthorReplyStatus(tq.AuthorStatusFail),
			tq.SetAuthorReplyServerMsg("not authorized"),
		),
	)
}

func (a CommandBasedAuthorizer) evaluate() bool {
	cmd := a.body.Args.Command()
	returnBool := func(c config.Action) bool {
		switch c {
		case config.PERMIT:
			return true
		default:
			return false
		}
	}
	for _, c := range a.user.Commands {
		if c.Name == "*" {
			// special condition of allow anything
			return returnBool(c.Action)
		}
		if c.Name != cmd {
			continue
		}
		if len(c.Match) == 0 {
			// cmd matches, but we have no conditions, so match it
			return returnBool(c.Action)
		}

		for _, regexish := range c.Match {
			if len(regexish) == 0 {
				continue
			}
			// guard against regexes that are not anchored to the start and end of the string
			if regexish[0] != regexStartByte {
				regexish = regexStartStr + regexish
			}
			if regexish[len(regexish)-1] != regexEndByte {
				regexish = regexish + regexEndStr
			}
			if matched, err := regexp.MatchString(regexish, a.body.Args.CommandArgsNoLE()); err != nil {
				a.Errorf(a.ctx, "bad regex detected; %v", err)
				return false
			} else if matched {
				return returnBool(c.Action)
			}
		}
	}
	return false
}
