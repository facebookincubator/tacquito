/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"context"
	"fmt"
	"io"
	"net"
	"testing"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/log"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

// BenchmarkPacketExchangeAsciiLoginSingleClient will test the full ascii login flow
// using a single client instance
func BenchmarkPacketExchangeAsciiLoginUsingSharedClient(b *testing.B) {
	logger := log.New(0, io.Discard) // no logs
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
	// record allocations regardless of go test -test.bench
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		for _, s := range test.Seq {
			c.Send(s.Packet)
		}
	}
}

// benchTest is used for allocation testing
type benchTest struct {
	name     string
	fn       func(b *testing.B)
	expected func(name string, r testing.BenchmarkResult)
}

// TestPacketExchangeAsciiLoginUsingSharedClientAllocation provides data on the allocs/op we do
// for a given request
func TestPacketExchangeAsciiLoginUsingSharedClientAllocation(t *testing.T) {
	tests := []benchTest{
		{
			name: "BenchmarkPacketExchangeAsciiLoginUsingSharedClient",
			fn:   BenchmarkPacketExchangeAsciiLoginUsingSharedClient,
			expected: func(name string, r testing.BenchmarkResult) {
				t.Log(spew.Sdump(r))
				expectedAllocs := 31
				actual := r.AllocsPerOp()
				assert.EqualValues(t, expectedAllocs, actual, fmt.Sprintf("%s allocations were not nominal; wanted %v got %v", name, expectedAllocs, actual))
			},
		},
	}
	for _, test := range tests {
		r := testing.Benchmark(test.fn)
		test.expected(test.name, r)
	}
}

// BenchmarkPacketExchangeAsciiLoginSingleClient will test the full ascii login flow
// using a new client instance each loop
func BenchmarkPacketExchangeAsciiLoginUsingNewClient(b *testing.B) {
	logger := log.New(0, io.Discard) // no logs
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
