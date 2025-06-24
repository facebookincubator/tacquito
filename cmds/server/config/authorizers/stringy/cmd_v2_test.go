/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package stringy

import (
	"context"
	"fmt"
	"testing"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"

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
func (r *mockedResponse) ReplyWithContext(ctx context.Context, v tq.EncoderDecoder, writer ...tq.Writer) (int, error) {
	return r.Reply(v)
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

func TestCommandsV2(t *testing.T) {
	logger := NewDefaultLogger()
	s := New(logger, EnableCmdV2(true))
	ctx := context.Background()
	tests := []stringyTest{
		// Original TestCommands test cases
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
		{
			name: "cisco; service=shell, cmd=check for regex boundaries",
			user: config.User{
				Name: "cisco",
				Commands: []config.Command{
					{
						Name:   "bash",
						Match:  []string{"cat.*"},
						Action: config.PERMIT,
					},
				},
			},
			request: newAuthorRequest("cisco", tq.Args{"service=shell", "cmd=bash", "cmd-arg=/etc/some_folder/file_name_contains_cat.sh"}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusFail {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusFail, response.got.Status))
				}
			},
		},
		{
			name: "cisco; service=shell, cmd=check that boundaries are not added if they are already set",
			user: config.User{
				Name: "cisco",
				Commands: []config.Command{
					{
						Name:   "bash",
						Match:  []string{"^cat.*$"},
						Action: config.PERMIT,
					},
				},
			},
			request: newAuthorRequest("cisco", tq.Args{"service=shell", "cmd=bash", "cmd-arg=cat", "cmd-arg=/etc/some_folder/file_name_contains_cat.sh"}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusPassAdd {
					assert.Fail(t, fmt.Sprintf("[%v] should have had a status of [%v] but got [%v]", name, tq.AuthorStatusPassAdd, response.got.Status))
				}
			},
		},
		{
			name: "[V2] user with only show version permission - should fail",
			user: config.User{
				Name: "only_permit_show_version",
				Commands: []config.Command{
					{
						Name:   "show",
						Match:  []string{"version"},
						Action: config.PERMIT,
					},
				},
			},
			request: newAuthorRequest("only_permit_show_version", tq.Args{
				"service=shell",
				"cmd=show",
				"cmd-arg=version",
				"cmd-arg=|",
				"cmd-arg=sudo curl -s -k -X GET https://localhost:8443/api/v1/health",
				"cmd-arg=|",
				"cmd-arg=grep -q \"UP\"",
				"cmd-arg=<cr>",
			}),
			validate: func(name string, response *mockedResponse) {
				// In V2 behavior, this should fail due to missing cmd=| permission
				if response.got.Status != tq.AuthorStatusFail {
					assert.Fail(t, fmt.Sprintf("[%v] should have failed due to missing cmd=| permission but got [%v]", name, response.got.Status))
				}
			},
		},
		{
			name: "[V2] user with show all permission - should fail",
			user: config.User{
				Name: "only_permit_show_all",
				Commands: []config.Command{
					{
						Name:   "show",
						Action: config.PERMIT,
					},
				},
			},
			request: newAuthorRequest("only_permit_show_all", tq.Args{
				"service=shell",
				"cmd=show",
				"cmd-arg=version",
				"cmd-arg=|",
				"cmd-arg=sudo curl -s -k -X GET https://localhost:8443/api/v1/health",
				"cmd-arg=|",
				"cmd-arg=grep -q \"UP\"",
				"cmd-arg=<cr>",
			}),
			validate: func(name string, response *mockedResponse) {
				// In V2 behavior, this should fail due to missing cmd=| permission
				if response.got.Status != tq.AuthorStatusFail {
					assert.Fail(t, fmt.Sprintf("[%v] should have failed due to missing cmd=| permission but got [%v]", name, response.got.Status))
				}
			},
		},
		{
			name: "[V2] user with show and pipe permission - should pass",
			user: config.User{
				Name: "permit_show_and_pipe",
				Commands: []config.Command{
					{
						Name:   "show",
						Action: config.PERMIT,
					},
					{
						Name:   "|",
						Action: config.PERMIT,
					},
				},
			},
			request: newAuthorRequest("permit_show_and_pipe", tq.Args{
				"service=shell",
				"cmd=show",
				"cmd-arg=version",
				"cmd-arg=|",
				"cmd-arg=sudo curl -s -k -X GET https://localhost:8443/api/v1/health",
				"cmd-arg=|",
				"cmd-arg=grep -q \"UP\"",
				"cmd-arg=<cr>",
			}),
			validate: func(name string, response *mockedResponse) {
				// In V2 behavior, this should pass with all required permissions
				if response.got.Status != tq.AuthorStatusPassAdd {
					assert.Fail(t, fmt.Sprintf("[%v] should have passed with all required permissions but got [%v]", name, response.got.Status))
				}
			},
		},
		{
			name: "[V2] user with all required permissions - should pass",
			user: config.User{
				Name: "permit_all_required",
				Commands: []config.Command{
					{
						Name:   "show",
						Action: config.PERMIT,
					},
					{
						Name:   "|",
						Action: config.PERMIT,
						Match:  []string{"sudo.*", "grep.*"},
					},
				},
			},
			request: newAuthorRequest("permit_all_required", tq.Args{
				"service=shell",
				"cmd=show",
				"cmd-arg=version",
				"cmd-arg=|",
				"cmd-arg=sudo curl -s -k -X GET https://localhost:8443/api/v1/health",
				"cmd-arg=|",
				"cmd-arg=grep -q \"UP\"",
				"cmd-arg=<cr>",
			}),
			validate: func(name string, response *mockedResponse) {
				// In V2 behavior, this should pass with all required permissions
				if response.got.Status != tq.AuthorStatusPassAdd {
					assert.Fail(t, fmt.Sprintf("[%v] should have passed with all required permissions but got [%v]", name, response.got.Status))
				}
			},
		},
		{
			name: "[V2] user with all required permissions - fails due to delimiters > permitted count",
			user: config.User{
				Name: "permit_all_required",
				Commands: []config.Command{
					{
						Name:   "show",
						Action: config.PERMIT,
					},
					{
						Name:   "|",
						Action: config.PERMIT,
						Match:  []string{"sudo.*", "grep.*"},
					},
				},
			},
			request: newAuthorRequest("permit_all_required", tq.Args{
				"service=shell",
				"cmd=show",
				"cmd-arg=version",
				"cmd-arg=|",
				"cmd-arg=sudo curl -s -k -X GET https://localhost:8443/api/v1/health",
				"cmd-arg=|",
				"cmd-arg=grep -q \"UP\"",
				"cmd-arg=|",
				"cmd-arg=grep -q \"Intf\"",
				"cmd-arg=|",
				"cmd-arg=sort",
				"cmd-arg=|",
				"cmd-arg=uniq",
				"cmd-arg=|",
				"cmd-arg=wc -l",
				"cmd-arg=<cr>",
			}),
			validate: func(name string, response *mockedResponse) {
				if response.got.Status != tq.AuthorStatusFail {
					assert.Fail(t, fmt.Sprintf("[%v] should have failed due to delimiters exceeding permitted count but got [%v]", name, response.got.Status))
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
