/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"context"
	"fmt"
	"testing"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"
	"github.com/facebookincubator/tacquito/cmds/server/config/authorizers/stringy"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

type stringyTest struct {
	name     string
	user     config.User
	request  tq.Request
	response mockedResponse
	validate func(name string, response *mockedResponse)
}

type mockedResponse struct {
	got *tq.AuthorReply
}

func (r mockedResponse) hasArgEqual(expected string) bool {
	for _, arg := range r.got.Args {
		if arg.String() == expected {
			return true
		}
	}
	return false
}

func (r *mockedResponse) Reply(v tq.EncoderDecoder) (int, error) {
	got, ok := v.(*tq.AuthorReply)
	if !ok {
		spew.Dump(v.Fields())
		return 0, fmt.Errorf("unable to assert encoderdecoder is a AuthorReply")
	}
	r.got = got
	return 0, nil
}

func (r *mockedResponse) Write(p *tq.Packet) (int, error) { return 0, nil }

func (r *mockedResponse) Next(next tq.Handler) {}

func (r *mockedResponse) RegisterWriter(mw tq.Writer) {}
func (r *mockedResponse) Context(ctx context.Context) {}

// newAuthorRequest ...
func newAuthorRequest(username string, args tq.Args) tq.Request {
	var hFlag tq.HeaderFlag
	packet := tq.NewPacket(
		tq.SetPacketHeader(
			tq.NewHeader(
				tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
				tq.SetHeaderType(tq.Authorize),
				tq.SetHeaderSeqNo(1),
				tq.SetHeaderFlag(hFlag),
				tq.SetHeaderSessionID(1),
			),
		),
		tq.SetPacketBodyUnsafe(
			tq.NewAuthorRequest(
				tq.SetAuthorRequestMethod(tq.AuthenMethodTacacsPlus),
				tq.SetAuthorRequestPrivLvl(tq.PrivLvlRoot),
				tq.SetAuthorRequestType(tq.AuthenTypeASCII),
				tq.SetAuthorRequestService(tq.AuthenServiceLogin),
				tq.SetAuthorRequestUser(tq.AuthenUser(username)),
				tq.SetAuthorRequestPort(tq.AuthenPort("an author port value")),
				tq.SetAuthorRequestRemAddr(tq.AuthenRemAddr("a remote address value")),
				tq.SetAuthorRequestArgs(args),
			),
		),
	)
	return tq.Request{
		Header: *packet.Header, Body: packet.Body[:], Context: context.Background(),
	}
}

func TestCommands(t *testing.T) {
	logger := newDefaultLogger(30)
	s := stringy.New(logger)
	ctx := context.Background()
	tests := []stringyTest{
		{
			name: "cisco; service=shell, cmd=show",
			user: config.User{
				Name: "cisco",
				Commands: []config.Command{
					{
						Name:   "show",
						Action: config.PERMIT,
					},
				},
			},
			request: newAuthorRequest("cisco", tq.Args{"service=shell", "cmd=show"}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusPassAdd {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassAdd, response.got.Status))
				}
			},
		},
		{
			name: "cisco; service=shell, cmd=show with wildcard regex",
			user: config.User{
				Name: "cisco",
				Commands: []config.Command{
					{
						Name:   "show",
						Match:  []string{".*"},
						Action: config.PERMIT,
					},
				},
			},
			request: newAuthorRequest("cisco", tq.Args{"service=shell", "cmd=show"}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusPassAdd {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassAdd, response.got.Status))
				}
			},
		},
		{
			name: "cisco; service=shell, cmd=show with splat wildcard",
			user: config.User{
				Name: "cisco",
				Commands: []config.Command{
					{
						Name:   "*",
						Action: config.PERMIT,
					},
				},
			},
			request: newAuthorRequest("cisco", tq.Args{"service=shell", "cmd=show"}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusPassAdd {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassAdd, response.got.Status))
				}
			},
		},
	}
	for _, test := range tests {
		logger.Infof(ctx, "running test [%v]", test.name)
		resp := &mockedResponse{}
		h, err := s.New(test.user)
		if err != nil {
			assert.Fail(t, "error from stringy factory; %v", err)
		}
		h.Handle(resp, test.request)
		test.validate(test.name, resp)
	}
}

func TestSessionsAndServices(t *testing.T) {
	logger := newDefaultLogger(30)
	s := stringy.New(logger)
	ctx := context.Background()
	tests := []stringyTest{
		{
			name: "cisco; service=shell, cmd=",
			user: config.User{
				Name: "cisco",
				Services: []config.Service{
					{
						Name: "shell",
						SetValues: []config.Value{
							{
								Name:   "priv-lvl",
								Values: []string{"15"},
							},
						},
					},
				},
			},
			request: newAuthorRequest("cisco", tq.Args{"service=shell", "cmd="}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusPassAdd {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassAdd, response.got.Status))
				}
				if !response.hasArgEqual("priv-lvl=15") {
					assert.Fail(t, fmt.Sprintf("we expected an optional arg of [priv-lvl=15] but got: %v", response.got.Args))
				}
			},
		},
		{
			name: "cisco; [service=shell, cmd*] with values that are duplicated in config",
			user: config.User{
				Name: "cisco",
				Services: []config.Service{
					{
						Name: "shell",
						SetValues: []config.Value{
							{
								Name:   "priv-lvl",
								Values: []string{"15"},
							},
							{
								Name:     "shell:roles",
								Values:   []string{"admin"},
								Optional: true,
							},
							{
								Name:   "priv-lvl",
								Values: []string{"15"},
							},
						},
					},
				},
			},
			request: newAuthorRequest("cisco", tq.Args{"service=shell", "cmd*"}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusPassRepl {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassRepl, response.got.Status))
				}
				if !response.hasArgEqual("priv-lvl=15") {
					assert.Fail(t, fmt.Sprintf("we expected an optional arg of [priv-lvl=15] but got: %v", response.got.Args))
				}
				if len(response.got.Args) != 2 {
					expected := []string{"priv-lvl=15 shell:roles*admin"}
					assert.Fail(t, fmt.Sprintf("received too many args %v, expected %v", response.got.Args, expected))
				}
			},
		},
		{
			name: "cisco; [service=shell, cmd*] with values that are duplicated in config and all required values",
			user: config.User{
				Name: "cisco",
				Services: []config.Service{
					{
						Name: "shell",
						SetValues: []config.Value{
							{
								Name:   "priv-lvl",
								Values: []string{"15"},
							},
							{
								Name:   "shell:roles",
								Values: []string{"admin"},
							},
							{
								Name:   "priv-lvl",
								Values: []string{"15"},
							},
						},
					},
				},
			},
			request: newAuthorRequest("cisco", tq.Args{"service=shell", "cmd*"}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusPassAdd {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassAdd, response.got.Status))
				}
				if !response.hasArgEqual("priv-lvl=15") {
					assert.Fail(t, fmt.Sprintf("we expected an optional arg of [priv-lvl=15] but got: %v", response.got.Args))
				}
				if len(response.got.Args) != 2 {
					expected := []string{"priv-lvl=15 shell:roles*admin"}
					assert.Fail(t, fmt.Sprintf("received too many args %v, expected %v", response.got.Args, expected))
				}
			},
		},
		{
			name: "cisco; [service=shell, cmd=] optional value",
			user: config.User{
				Name: "cisco",
				Services: []config.Service{
					{
						Name: "shell",
						SetValues: []config.Value{
							{
								Name:     "priv-lvl",
								Values:   []string{"15"},
								Optional: true,
							},
						},
					},
				},
			},
			request: newAuthorRequest("cisco", tq.Args{"service=shell", "cmd="}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusPassRepl {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassRepl, response.got.Status))
				}
				if !response.hasArgEqual("priv-lvl*15") {
					assert.Fail(t, fmt.Sprintf("we expected an optional arg of [priv-lvl*15] but got: %v", response.got.Args))
				}
			},
		},
		{
			name: "cisco; [service=shell, cmd=] optional value and also one that was not requested",
			user: config.User{
				Name: "cisco",
				Services: []config.Service{
					{
						Name: "shell",
						SetValues: []config.Value{
							{
								Name:     "priv-lvl",
								Values:   []string{"15"},
								Optional: true,
							},
						},
					},
					{
						Name: "not-requested",
						SetValues: []config.Value{
							{
								Name:     "nope",
								Values:   []string{"nada"},
								Optional: true,
							},
						},
					},
				},
			},
			request: newAuthorRequest("cisco", tq.Args{"service=shell", "cmd="}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusPassRepl {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassRepl, response.got.Status))
				}
				if !response.hasArgEqual("priv-lvl*15") {
					assert.Fail(t, fmt.Sprintf("we expected an optional arg of [priv-lvl*15] but got: %v", response.got.Args))
				}
				if response.hasArgEqual("nope*nada") {
					assert.Fail(t, fmt.Sprintf("we received an unexpected optional arg of [nope*nada]: %v", response.got.Args))
				}
			},
		},
		{
			name: "cisco; [service=shell, cmd=] required value and an optional",
			user: config.User{
				Name: "cisco",
				Services: []config.Service{
					{
						Name: "shell",
						SetValues: []config.Value{
							{
								Name:   "priv-lvl",
								Values: []string{"15"},
							},
						},
					},
					{
						Name: "not-requested",
						SetValues: []config.Value{
							{
								Name:     "nope",
								Values:   []string{"nada"},
								Optional: true,
							},
						},
					},
				},
			},
			request: newAuthorRequest("cisco", tq.Args{"service=shell", "cmd="}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusPassAdd {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassAdd, response.got.Status))
				}
				if !response.hasArgEqual("priv-lvl=15") {
					assert.Fail(t, fmt.Sprintf("we expected an arg of [priv-lvl=15] but got: %v", response.got.Args))
				}
				if response.hasArgEqual("nope*nada") {
					assert.Fail(t, fmt.Sprintf("we received an unexpected optional arg of [nope*nada]: %v", response.got.Args))
				}
			},
		},
		{
			name: "junos; [service=junos-exec]",
			user: config.User{
				Name: "junos",
				Services: []config.Service{
					{
						Name: "junos-exec",
						SetValues: []config.Value{
							{
								Name:   "local-user-name",
								Values: []string{"megamaid"},
							},
						},
					},
				},
				Commands: []config.Command{
					{
						Name: "foo", Action: config.PERMIT,
					},
				},
			},
			request: newAuthorRequest("junos", tq.Args{"service=junos-exec"}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusPassAdd {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassAdd, response.got.Status))
				}
				if !response.hasArgEqual("local-user-name=megamaid") {
					assert.Fail(t, fmt.Sprintf("we expected an arg of [local-user-name=megamaid] but got: %v", response.got.Args))
				}
			},
		},
		{
			name: "junos; [service=junos-exec] with splat",
			user: config.User{
				Name: "junos",
				Services: []config.Service{
					{
						Name: "junos-exec",
						SetValues: []config.Value{
							{
								Name:   "local-user-name",
								Values: []string{"megamaid"},
							},
						},
					},
				},
				Commands: []config.Command{
					{
						Name: "*", Action: config.PERMIT,
					},
				},
			},
			request: newAuthorRequest("junos", tq.Args{"service=junos-exec"}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusPassAdd {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassAdd, response.got.Status))
				}
				if !response.hasArgEqual("local-user-name=megamaid") {
					assert.Fail(t, fmt.Sprintf("we expected an arg of [local-user-name=megamaid] but got: %v", response.got.Args))
				}
			},
		},
		{
			name: "nxos/firepower; [service=shell, cmd=, cisco-av-pair*, shell:roles*]",
			user: config.User{
				Name: "nxos/firepower",
				Services: []config.Service{
					{
						Name: "shell",
						SetValues: []config.Value{
							{
								Name:   "priv-lvl",
								Values: []string{"15"},
							},
							{
								Name:     "shell:roles",
								Values:   []string{"admin"},
								Optional: true,
							},
							{
								Name:     "shell:roles",
								Values:   []string{"network-admin vdc-admin"},
								Optional: true,
							},
						},
					},
				},
				Commands: []config.Command{
					{
						Name: "nada", Action: config.PERMIT,
					},
				},
			},
			request: newAuthorRequest("nxos/firepower", tq.Args{"service=shell", "cmd=", "cisco-av-pair*", "shell:roles*"}),
			validate: func(name string, response *mockedResponse) {
				// spew.Dump(response.got)
				if response.got.Status != tq.AuthorStatusPassRepl {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassRepl, response.got.Status))
				}
				if !response.hasArgEqual("shell:roles*admin") {
					assert.Fail(t, fmt.Sprintf("we expected an arg of [shell:roles*admin] but got: %v", response.got.Args))
				}
				if !response.hasArgEqual("shell:roles*network-admin vdc-admin") {
					assert.Fail(t, fmt.Sprintf("we expected an arg of [shell:roles*network-admin vdc-admin] but got: %v", response.got.Args))
				}
			},
		},
	}
	for _, test := range tests {
		logger.Infof(ctx, "running test [%v]", test.name)
		resp := &mockedResponse{}
		h, err := s.New(test.user)
		if err != nil {
			assert.FailNow(t, "error from stringy factory; %v", err)
		}
		h.Handle(resp, test.request)
		test.validate(test.name, resp)
	}
}
