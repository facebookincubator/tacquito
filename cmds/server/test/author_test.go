/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"context"
	"fmt"
	"net"
	"testing"

	tq "github.com/facebookincubator/tacquito"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func basicAuthorPacket(username tq.AuthenUser, args tq.Args) *tq.Packet {
	return tq.NewPacket(
		tq.SetPacketHeader(
			tq.NewHeader(
				tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
				tq.SetHeaderType(tq.Authorize),
				tq.SetHeaderRandomSessionID(),
			),
		),
		tq.SetPacketBodyUnsafe(
			tq.NewAuthorRequest(
				tq.SetAuthorRequestMethod(tq.AuthenMethodTacacsPlus),
				tq.SetAuthorRequestPrivLvl(tq.PrivLvlRoot),
				tq.SetAuthorRequestType(tq.AuthenTypeASCII),
				tq.SetAuthorRequestService(tq.AuthenServiceLogin),
				tq.SetAuthorRequestUser(username),
				tq.SetAuthorRequestArgs(args),
			),
		),
	)
}

func authorCmdBased(t *testing.T) []Test {
	return []Test{
		{
			Name:   "authorization cmd flow 1",
			Secret: []byte("fooman"),
			Seq: []Sequence{
				{
					Packet: basicAuthorPacket("mr_uses_group", tq.Args{"service=shell", "cmd=configure\n", "cmd-arg=terminal\n", "cmd-arg=<cr>"}),
					ValidateBody: func(response []byte) error {
						var body tq.AuthorReply
						if err := tq.Unmarshal(response, &body); err != nil {
							return err
						}
						if body.Status != tq.AuthorStatusPassAdd {
							spew.Dump(body)
							return fmt.Errorf("failed to match AuthorStatusPassAdd")
						}
						return nil
					},
				},
			},
		},
		{
			Name:   "authorization cmd flow 2 (line endings)",
			Secret: []byte("fooman"),
			Seq: []Sequence{
				{
					Packet: basicAuthorPacket("mr_uses_group", tq.Args{"service=shell", "cmd=configure", "cmd-arg=terminal", "cmd-arg=<cr>"}),
					ValidateBody: func(response []byte) error {
						var body tq.AuthorReply
						if err := tq.Unmarshal(response, &body); err != nil {
							return err
						}
						if body.Status != tq.AuthorStatusPassAdd {
							spew.Dump(body)
							return fmt.Errorf("failed to match AuthorStatusPassAdd")
						}
						return nil
					},
				},
			},
		},
	}
}

func authorSessionBased(t *testing.T) []Test {
	return []Test{
		{
			Name:   "authorization session flow 1",
			Secret: []byte("fooman"),
			Seq: []Sequence{
				{
					Packet: basicAuthorPacket("mr_uses_group", tq.Args{"service=shell", "cmd=", "cisco-av-pair*", "shell:roles*"}),
					ValidateBody: func(response []byte) error {
						var body tq.AuthorReply
						if err := tq.Unmarshal(response, &body); err != nil {
							return err
						}
						if body.Status != tq.AuthorStatusPassRepl {
							spew.Dump(body)
							return fmt.Errorf("failed to match AuthorStatusPassRepl")
						}
						expectedArgs := tq.Args{"shell:roles*admin", "shell:roles*network-admin vdc-admin", "priv-lvl*15"}
						if !assert.Equal(t, expectedArgs, body.Args) {
							spew.Dump(body)
							return fmt.Errorf("failed to match Args")
						}
						return nil
					},
				},
			},
		},
		{
			Name:   "authorization session flow 2 cmd* naked",
			Secret: []byte("fooman"),
			Seq: []Sequence{
				{
					Packet: basicAuthorPacket("mr_uses_group", tq.Args{"service=shell", "cmd*"}),
					ValidateBody: func(response []byte) error {
						var body tq.AuthorReply
						if err := tq.Unmarshal(response, &body); err != nil {
							return err
						}
						if body.Status != tq.AuthorStatusPassRepl {
							spew.Dump(body)
							return fmt.Errorf("failed to match AuthorStatusPassRepl")
						}
						expectedArgs := tq.Args{"priv-lvl*15"}
						if !assert.Equal(t, expectedArgs, body.Args) {
							spew.Dump(body)
							return fmt.Errorf("failed to match Args")
						}
						return nil
					},
				},
			},
		},
	}
}
func TestAuthorize(t *testing.T) {
	logger := NewDefaultLogger(30) // no logs
	ctx := context.Background()
	sp, err := MockSecretProvider(ctx, logger, "testdata/test_config.yaml")
	assert.NoError(t, err)

	listener, err := net.Listen("tcp6", "[::1]:0")
	assert.NoError(t, err)
	tcpListener := listener.(*net.TCPListener)

	s := tq.NewServer(logger, sp)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := s.Serve(ctx, tcpListener); err != nil {
			assert.NoError(t, err)
		}
	}()

	// append tests
	tests := []Test{}
	tests = append(tests, authorCmdBased(t)...)
	tests = append(tests, authorSessionBased(t)...)

	for _, test := range tests {
		c, err := tq.NewClient(tq.SetClientDialer("tcp6", listener.Addr().String(), test.Secret))
		assert.NoError(t, err)
		for _, s := range test.Seq {
			resp, err := c.Send(s.Packet)
			assert.NoError(t, err, "test name [%v]", test.Name)
			err = s.ValidateBody(resp.Body)
			assert.NoError(t, err, "test name [%v]", test.Name)
		}
		c.Close()
	}
}

func TestAuthorizePacketNoAuthen(t *testing.T) {
	username := tq.AuthenUser("testuser")
	args := tq.Args{"service=shell", "cmd=configure\n", "cmd-arg=terminal\n", "cmd-arg=<cr>"}
	az := tq.NewAuthorRequest(
		tq.SetAuthorRequestMethod(tq.AuthenMethodTacacsPlus),
		tq.SetAuthorRequestPrivLvl(tq.PrivLvlRoot),
		tq.SetAuthorRequestType(tq.AuthenTypeNotSet),
		tq.SetAuthorRequestService(tq.AuthenServiceLogin),
		tq.SetAuthorRequestUser(username),
		tq.SetAuthorRequestArgs(args),
	)

	if err := az.Validate(); err != nil {
		t.Fatalf("unexpected error %v", err)
	}
}
