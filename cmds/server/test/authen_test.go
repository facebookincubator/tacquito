/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"context"
	"net"
	"testing"

	tq "github.com/facebookincubator/tacquito"

	"github.com/stretchr/testify/assert"
)

func TestAuthenticate(t *testing.T) {
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

	tests := []Test{
		ASCIILoginFullFlow(),
		ASCIILoginEnable(),
		PapLoginFlow(),
	}

	tests = append(tests, GetASCIIEnableAbortTests()...)
	tests = append(tests, GetASCIILoginAbortTests()...)
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

func TestAuthenticateNoAuthen(t *testing.T) {
	as := tq.NewAuthenStart(
		tq.SetAuthenStartAction(tq.AuthenActionLogin),
		tq.SetAuthenStartPrivLvl(tq.PrivLvlUser),
		tq.SetAuthenStartType(tq.AuthenTypeNotSet),
		tq.SetAuthenStartService(tq.AuthenServiceLogin),
		tq.SetAuthenStartPort("tty0"),
		tq.SetAuthenStartRemAddr("foo"),
	)
	if err := as.Validate(); err == nil {
		t.Fatalf("expected error %v", err)
	}
}
