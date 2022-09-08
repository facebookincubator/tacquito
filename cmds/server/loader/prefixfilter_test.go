/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package loader

import (
	"fmt"
	"net"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

// prefixBuilder converts cidr string values to *net.IPNet values, ignoring
// invalid ones.
func testPrefixBuilder(prefixes ...string) []*net.IPNet {
	allowed := make([]*net.IPNet, 0, len(prefixes))
	for _, cidr := range prefixes {
		if _, ipNet, _ := net.ParseCIDR(cidr); ipNet != nil {
			allowed = append(allowed, ipNet)
		}
	}
	return allowed
}

func TestPrefixAllow(t *testing.T) {
	tests := []struct {
		name     string
		allowed  []*net.IPNet
		remote   net.Addr
		expected bool
	}{
		{
			name:     "test1",
			allowed:  testPrefixBuilder("2401:db00::/64"),
			remote:   &net.TCPAddr{IP: net.ParseIP("2001:db8::68")},
			expected: false,
		},
		{
			name:     "test2",
			allowed:  testPrefixBuilder("2401:db00::/64"),
			remote:   &net.TCPAddr{IP: net.ParseIP("2401:db00::")},
			expected: true,
		},
		{
			name:     "test3",
			allowed:  testPrefixBuilder("2401:db00::/64"),
			remote:   &net.TCPAddr{IP: net.ParseIP("2401:db00::1")},
			expected: true,
		},
		{
			name:     "test4 - fail open if nothing provided to filter",
			allowed:  nil,
			remote:   &net.TCPAddr{IP: net.ParseIP("2401:db00::1")},
			expected: true,
		},
	}
	for _, test := range tests {
		f := newPrefixFilter(test.allowed)
		spew.Dump(test)
		assert.Equal(t, test.expected, f.allow(test.remote), fmt.Sprintf("failed %v", test.name))
	}
}

func TestPrefixDeny(t *testing.T) {
	tests := []struct {
		name     string
		deny     []*net.IPNet
		remote   net.Addr
		expected bool
	}{
		{
			name:     "test1",
			deny:     testPrefixBuilder("2401:db00::/64"),
			remote:   &net.TCPAddr{IP: net.ParseIP("2001:db8::68")},
			expected: false,
		},
		{
			name:     "test2",
			deny:     testPrefixBuilder("2401:db00::/64"),
			remote:   &net.TCPAddr{IP: net.ParseIP("2401:db00::")},
			expected: true,
		},
		{
			name:     "test3",
			deny:     testPrefixBuilder("2401:db00::/64"),
			remote:   &net.TCPAddr{IP: net.ParseIP("2402:db00::1")},
			expected: false,
		},
		{
			name:     "test4 - fail open if nothing provided to filter",
			deny:     nil,
			remote:   &net.TCPAddr{IP: net.ParseIP("2401:db00::1")},
			expected: false,
		},
	}
	for _, test := range tests {
		f := newPrefixFilter(test.deny)
		spew.Dump(test)
		assert.Equal(t, test.expected, f.deny(test.remote), fmt.Sprintf("failed %v", test.name))
	}
}
