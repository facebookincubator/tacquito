/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"crypto/tls"
	"net"
)

// SetClientTLSDialer creates a client that connects to the server using TLS.
// network and address specify the server to connect to.
// tlsConfig is the TLS configuration to use for the connection.
func SetClientTLSDialer(network, address string, tlsConfig *tls.Config) ClientOption {
	return func(c *Client) error {
		// Connect to the server using TLS
		conn, err := tls.Dial(network, address, tlsConfig)
		if err != nil {
			return err
		}
		c.crypter = newCrypter(nil, conn, false, true)
		return nil
	}
}

// SetClientTLSDialerWithLocalAddr creates a client that connects to the server using TLS,
// allowing specification of the local address to connect from.
// network and raddr specify the server to connect to.
// laddr specifies the local address to connect from.
// tlsConfig is the TLS configuration to use for the connection.
func SetClientTLSDialerWithLocalAddr(network, raddr, laddr string, tlsConfig *tls.Config) ClientOption {
	return func(c *Client) error {
		// Resolve the local address if provided
		var localAddr *net.TCPAddr
		var err error
		if laddr != "" {
			localAddr, err = net.ResolveTCPAddr(network, laddr)
			if err != nil {
				return err
			}
		}

		// Create a dialer with the local address
		dialer := &net.Dialer{
			LocalAddr: localAddr,
		}

		// Connect to the server using TLS with the dialer
		conn, err := tls.DialWithDialer(dialer, network, raddr, tlsConfig)
		if err != nil {
			return err
		}
		c.crypter = newCrypter(nil, conn, false, true)
		return nil
	}
}
