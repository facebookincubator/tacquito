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

func acctFlagStart(t *testing.T) []Test {
	var f tq.AcctRequestFlag
	f.Set(tq.AcctFlagStart)
	return []Test{
		{
			Name:   "accounting flag start",
			Secret: []byte("fooman"),
			Seq: []Sequence{
				{
					Packet: tq.NewPacket(
						tq.SetPacketHeader(
							tq.NewHeader(
								tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
								tq.SetHeaderType(tq.Accounting),
								tq.SetHeaderSessionID(1),
							),
						),
						tq.SetPacketBodyUnsafe(
							tq.NewAcctRequest(
								tq.SetAcctRequestFlag(f),
								tq.SetAcctRequestMethod(tq.AuthenMethodTacacsPlus),
								tq.SetAcctRequestPrivLvl(tq.PrivLvlRoot),
								tq.SetAcctRequestType(tq.AuthenTypeASCII),
								tq.SetAcctRequestService(tq.AuthenServiceLogin),
								tq.SetAcctRequestUser("mr_uses_group"),
								tq.SetAcctRequestArgs(tq.Args{"cmd=show", "cmd-arg=system"}),
							),
						),
					),
					ValidateBody: func(response []byte) error {
						var body tq.AcctReply
						if err := tq.Unmarshal(response, &body); err != nil {
							return err
						}
						if body.Status != tq.AcctReplyStatusSuccess {
							spew.Dump(body)
							return fmt.Errorf("failed to match AcctReplyStatusSuccess")
						}
						return nil
					},
				},
			},
		},
	}

}

func TestAccounting(t *testing.T) {
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
	tests = append(tests, acctFlagStart(t)...)

	for _, test := range tests {
		c, err := tq.NewClient(tq.SetClientDialer("tcp6", listener.Addr().String(), test.Secret))
		assert.NoError(t, err)
		assert.NotNil(t, c, "client was nil, bad")
		for _, s := range test.Seq {
			resp, err := c.Send(s.Packet)
			assert.NoError(t, err, "test name [%v]", test.Name)
			assert.NotNil(t, resp, "response was nil?")
			err = s.ValidateBody(resp.Body)
			assert.NoError(t, err, "test name [%v]", test.Name)
		}
		c.Close()
	}
}

func TestAccountingPacketNoAuthen(t *testing.T) {
	var f tq.AcctRequestFlag
	f.Set(tq.AcctFlagStart)
	ac := tq.NewAcctRequest(
		tq.SetAcctRequestFlag(f),
		tq.SetAcctRequestMethod(tq.AuthenMethodTacacsPlus),
		tq.SetAcctRequestPrivLvl(tq.PrivLvlRoot),
		tq.SetAcctRequestType(tq.AuthenTypeNotSet),
		tq.SetAcctRequestService(tq.AuthenServiceLogin),
		tq.SetAcctRequestUser("mr_uses_group"),
		tq.SetAcctRequestArgs(tq.Args{"cmd=show", "cmd-arg=system"}),
	)
	if err := ac.Validate(); err != nil {
		t.Fatalf("unexpected error %v", err)
	}
}
