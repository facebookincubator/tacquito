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

// NewCommandBasedAuthorizerV2 will return a new authorizer that splits req args based on delimiter such as "|" and treats the delimited
// args as separate inputs. If initial request params are not suitable for command based, it returns nil
func NewCommandBasedAuthorizerV2(ctx context.Context, l loggerProvider, b tq.AuthorRequest, u config.User) *CommandBasedAuthorizerV2 {
	// commands are also only evaluated if service == shell
	if b.Args.Service() != "shell" {
		return nil
	}
	// cmd= and cmd* are not allowed. the command cmd=show etc must be specified
	// cmd*show is also not allowed. Only the mandatory separator is considered valid
	a, s, v := b.Args.CommandSplit()
	if a != "cmd" || s != "=" || v == "" {
		return nil
	}
	return &CommandBasedAuthorizerV2{ctx: ctx, loggerProvider: l, body: b, user: u}
}

// CommandBasedAuthorizerV2 provides a command based authorizer which works similar to the
// original CommandBasedAuthorizer, but with a difference that it treats req args as a list of commands
// split on a delimiter such as "|"
type CommandBasedAuthorizerV2 struct {
	loggerProvider
	ctx  context.Context
	body tq.AuthorRequest
	user config.User
}

// Handle will respond with failures or accepts as needed
func (a CommandBasedAuthorizerV2) Handle(response tq.Response, request tq.Request) {
	if splits := a.body.Args.Split("|"); splits != nil {
		for _, args := range splits {
			if !a.evaluate(args) {
				a.Debugf(request.Context, "user [%v] failed command based authorization. Args=%v", a.user.Name, args)
				stringyHandleAuthorizeFailv2.Inc()
				response.Reply(
					tq.NewAuthorReply(
						tq.SetAuthorReplyStatus(tq.AuthorStatusFail),
						tq.SetAuthorReplyServerMsg("not authorized"),
					),
				)
				return
			}
		}
	} else {
		a.Debugf(request.Context, "user [%v] failed command based authorization; command had more than %d delimiters", a.user.Name, tq.MaxSplitCount)
		response.Reply(
			tq.NewAuthorReply(
				tq.SetAuthorReplyStatus(tq.AuthorStatusFail),
				tq.SetAuthorReplyServerMsg("not authorized"),
			),
		)
		return
	}

	stringyHandleAuthorizeAcceptPassAddv2.Inc()
	response.Reply(
		tq.NewAuthorReply(
			tq.SetAuthorReplyStatus(tq.AuthorStatusPassAdd),
		),
	)
}

func (a CommandBasedAuthorizerV2) evaluate(args tq.Args) bool {
	cmd := args.Command()
	cmdArgs := args.CommandArgsNoLE()

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
			if matched, err := regexp.MatchString(regexish, cmdArgs); err != nil {
				a.Errorf(a.ctx, "bad regex detected; %v", err)
				return false
			} else if matched {
				return returnBool(c.Action)
			}
		}
	}
	return false
}
