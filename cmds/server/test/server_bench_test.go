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

// BenchmarkPacketExchangeAsciiLoginSingleClient will test the full ascii login flow
// using a single client instance
func BenchmarkPacketExchangeAsciiLoginUsingSharedClient(b *testing.B) {
	logger := NewDefaultLogger(0) // no logs
	ctx := context.Background()
	sp, err := MockSecretProvider(ctx, logger, "testdata/test_config.yaml")
	assert.NoError(b, err)

	listener, err := net.Listen("tcp6", "[::1]:0")
	assert.NoError(b, err)
	tcpListener := listener.(*net.TCPListener)

	s := tq.NewServer(logger, sp)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := s.Serve(ctx, tcpListener); err != nil {
			assert.NoError(b, err)
		}
	}()

	c, err := tq.NewClient(tq.SetClientDialer("tcp6", listener.Addr().String(), []byte("fooman")))
	assert.NoError(b, err)
	defer c.Close()

	test := ASCIILoginFullFlow()
	for n := 0; n < b.N; n++ {
		for _, s := range test.Seq {
			c.Send(s.Packet)
		}
	}
}

// BenchmarkPacketExchangeAsciiLoginSingleClient will test the full ascii login flow
// using a new client instance each loop
func BenchmarkPacketExchangeAsciiLoginUsingNewClient(b *testing.B) {
	logger := NewDefaultLogger(0) // no logs
	ctx := context.Background()
	sp, err := MockSecretProvider(ctx, logger, "testdata/test_config.yaml")
	assert.NoError(b, err)

	listener, err := net.Listen("tcp6", "[::1]:0")
	assert.NoError(b, err)
	tcpListener := listener.(*net.TCPListener)

	s := tq.NewServer(logger, sp)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := s.Serve(ctx, tcpListener); err != nil {
			assert.NoError(b, err)
		}
	}()

	test := ASCIILoginFullFlow()
	for n := 0; n < b.N; n++ {
		c, err := tq.NewClient(tq.SetClientDialer("tcp6", listener.Addr().String(), []byte("fooman")))
		assert.NoError(b, err)
		for _, s := range test.Seq {
			c.Send(s.Packet)
		}
		c.Close()
	}
}
