/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package loader

import (
	"net"
)

// newPrefixFilter creates a basic prefix filter for any incoming connections.  If
// this is provided to the server, we will never speak to any clients that do not
// pass this check.  This allows other providers to determine how to best interact
// with a client and offloads some basic security checks
func newPrefixFilter(prefixes []*net.IPNet) *prefixFilter {
	f := &prefixFilter{known: make(map[string]struct{})}
	for _, ipnet := range prefixes {
		f.known[ipnet.String()] = struct{}{}
	}
	return f
}

// prefixFilter holds a cache of prefixes we are allowed to speak to
type prefixFilter struct {
	known map[string]struct{}
}

// match determines if we are matched to speak/not speak to a client's source prefix.  If no
// prefixes are provided, we fail open.
func (p prefixFilter) match(addr *net.TCPAddr) bool {
	for cidr := range p.known {
		_, ipNet, _ := net.ParseCIDR(cidr)
		if ipNet != nil && ipNet.Contains(addr.IP) {
			return true
		}
	}
	return false
}

// deny is our deny list
func (p prefixFilter) deny(remote net.Addr) bool {
	if len(p.known) < 1 {
		return false
	}
	addr, ok := remote.(*net.TCPAddr)
	if !ok {
		prefixFilterDenied.Inc()
		return true
	}
	if p.match(addr) {
		prefixFilterDenied.Inc()
		return true
	}
	prefixFilterAllowed.Inc()
	return false
}

// allow is our allow list
func (p prefixFilter) allow(remote net.Addr) bool {
	if len(p.known) < 1 {
		return true
	}
	addr, ok := remote.(*net.TCPAddr)
	if !ok {
		prefixFilterDenied.Inc()
		return false
	}
	if p.match(addr) {
		prefixFilterAllowed.Inc()
		return true
	}
	prefixFilterDenied.Inc()
	return false
}
