/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package proxy

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestPeekHAProxy(t *testing.T) {
	tests := []struct {
		line          []byte
		clientAddress string
		clientNetwork string
		remoteAddress string
		remoteNetwork string
		errorExpected func(t *testing.T, err error)
	}{
		{
			line:          []byte("PROXY TCP6 2401:db00:eef0:1120:3520:0000:1802:1 2401:db00:eef0:1120:3520:0000:1802:61ee 100 200\r\n\x00"),
			clientAddress: "[2401:db00:eef0:1120:3520:0000:1802:1]:100",
			clientNetwork: "tcp6",
			remoteAddress: "[2401:db00:eef0:1120:3520:0000:1802:61ee]:200",
			remoteNetwork: "tcp6",
		},
		{
			line:          []byte("PROXY TCP 2401:db00:eef0:1120:3520:0000:1802:2 2401:db00:eef0:1120:3520:0000:1802:61ee 100 200\r\n\x00"),
			clientAddress: "[2401:db00:eef0:1120:3520:0000:1802:2]:100",
			clientNetwork: "tcp",
			remoteAddress: "[2401:db00:eef0:1120:3520:0000:1802:61ee]:200",
			remoteNetwork: "tcp",
		},
		{
			line:          []byte("PROXY TCP5 2401:db00:eef0:1120:3520:0000:1802:3 2401:db00:eef0:1120:3520:0000:1802:61ee 100 200\r\n\x00"),
			clientAddress: ":",
			remoteAddress: ":",
			errorExpected: func(t *testing.T, err error) {
				var expectedErr net.UnknownNetworkError
				if errors.As(err, &expectedErr) {
					return
				}
				assert.Fail(t, fmt.Sprintf("expected a net.UnknownNetworkError, got %v", err))
			},
		},
		{
			line:          []byte("PROXY TCP4 1.1.1.1 2.2.2.2 100 200\r\n\x00"),
			clientAddress: "1.1.1.1:100",
			clientNetwork: "tcp4",
			remoteAddress: "2.2.2.2:200",
			remoteNetwork: "tcp4",
		},
		{
			line:          []byte("asdfjfkldj;lalsdkjflkjdsl;ajl;sdjfioew;aoijsldjfaol;wieja;olsdjfoai;wejafl"),
			clientAddress: ":",
			remoteAddress: ":",
			errorExpected: func(t *testing.T, err error) {
				var expectedErr HeaderStringMalformed
				if errors.As(err, &expectedErr) {
					return
				}
				assert.Fail(t, fmt.Sprintf("expected a HeaderStringMalformed, got %v", err))
			},
		},
		{
			line:          []byte("PROXY"),
			clientAddress: ":",
			remoteAddress: ":",
			errorExpected: func(t *testing.T, err error) {
				var expectedErr HeaderStringMalformed
				if errors.As(err, &expectedErr) {
					return
				}
				assert.Fail(t, fmt.Sprintf("expected a HeaderStringMalformed, got %v", err))
			},
		},
	}
	for _, test := range tests {
		pw := NewHeader(&addr{}, &addr{})
		_, err := pw.Write(test.line)
		if test.errorExpected != nil {
			test.errorExpected(t, err)
		} else {
			assert.NoError(t, err)
		}

		spew.Dump(pw)
		assert.Equal(t, test.clientAddress, pw.client.String())
		assert.Equal(t, test.clientNetwork, pw.client.Network())
		assert.Equal(t, test.remoteAddress, pw.remote.String())
		assert.Equal(t, test.remoteNetwork, pw.remote.Network())
	}
}
