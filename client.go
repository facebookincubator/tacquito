/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"fmt"
	"net"
)

// ClientOption is a setter type for Client
type ClientOption func(c *Client) error

// SetClientDialer see net.ResolveTCPAddr for details, this follows
// the same input requirements for network and address.  It will then use net.DialTCP
// with a nil source addr and a constructed TCPAddr from the provided network and address.
// A secret for the connection must also be provided.
func SetClientDialer(network, address string, secret []byte) ClientOption {
	return func(c *Client) error {
		tcpAddr, err := net.ResolveTCPAddr(network, address)
		if err != nil {
			return err
		}
		conn, err := net.DialTCP(network, nil, tcpAddr)
		if err != nil {
			return err
		}
		c.crypter = newCrypter(secret, conn, false)
		return nil
	}
}

// SetClientDialerWithLocalAddr see net.ResolveTCPAddr for details, this follows
// the same input requirements for network and address.  raddr is the destination tcp address
// to dial to, and laddr is the client address to dial from, if set to an empty string, then
// the function will fall back to DialTCP's default selection of a local interface
// with a nil source addr and a constructed TCPAddr from the provided network and address.
// A secret for the connection must also be provided.
func SetClientDialerWithLocalAddr(network, raddr, laddr string, secret []byte) ClientOption {
	return func(c *Client) error {
		localAddr, err := net.ResolveTCPAddr(network, laddr)
		if err != nil {
			fmt.Printf("unable to assign local address %v:%v, a default address will be chosen", laddr, err)
		}
		tcpAddr, err := net.ResolveTCPAddr(network, raddr)
		if err != nil {
			return err
		}
		conn, err := net.DialTCP(network, localAddr, tcpAddr)
		if err != nil {
			return err
		}
		c.crypter = newCrypter(secret, conn, false)
		return nil
	}
}

// NewClient creates a new client
func NewClient(opts ...ClientOption) (*Client, error) {
	c := &Client{}
	defaults := []ClientOption{}
	opts = append(defaults, opts...)
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// Client base client implementation for server/client communication
type Client struct {
	crypter *crypter
}

// Send sends a packet to the server and decodes the response.  If multiple packet exchanges are
// necessary, the caller will need to call this method repeatedly to achieve the desired
// result.
func (c *Client) Send(p *Packet) (*Packet, error) {
	_, err := c.crypter.write(p)
	if err != nil {
		return nil, err
	}
	return c.crypter.read()

}

// Close ...
func (c *Client) Close() error {
	return c.crypter.Close()
}
