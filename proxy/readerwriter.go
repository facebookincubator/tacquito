/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package proxy provides a reader writer that can add PROXY ASCII strings to bytes
// or strip the PROXY ASCII strings from bytes.  The context is appropriately
// updated against the underlying so as to preserve the remote host's ability to "see" the client
// address and port.
// Only the ASCII portion is implemented from http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
)

// MaxProxyHeader is the max size needed to scan for and obtain a proxy header string
const (
	MaxProxyHeader = 108
)

// HeaderStringMalformed is returned when we found a PROXY header string but it was malformed
// for some reason
type HeaderStringMalformed string

func (e HeaderStringMalformed) Error() string { return string(e) }

// NewHeader returns a ReaderWriter that implements the HA PROXY ASCII encode/decode
func NewHeader(client, remote net.Addr) *Header {
	return &Header{client: client, remote: remote}
}

// Header will operate on []byte to add or remove the ASCII proxy header.  This type
// can be composed into another to satisfy a net.Conn if desired.  Be sure not to override
// LocalAddr and RemoteAddr in doing so and take care to sequence the Read/Write calls.
type Header struct {
	client net.Addr
	remote net.Addr
}

func (h *Header) Read(b []byte) (int, error) {
	header := h.proxyHeader()
	if len(b) < len(header) {
		return 0, io.ErrShortBuffer
	}
	return copy(b, header), nil
}

func (h *Header) proxyHeader() []byte {
	// spec requires uppercase for network
	network := strings.ToUpper(h.client.Network())
	clientIP, clientPort := getIPPort(h.client)
	if clientIP == nil {
		return nil
	}
	proxyIP, proxyPort := getIPPort(h.remote)
	if proxyIP == nil {
		return nil
	}
	// PROXY <inet protocol> <client IP> <proxy IP> <client port> <proxy port>\r\n
	return []byte(
		fmt.Sprintf(
			"PROXY %s %s %s %d %d\r\n\x00",
			network,
			clientIP,
			proxyIP,
			clientPort,
			proxyPort,
		),
	)
}

// Write will take a well formed proxy header and write it to self.
// b will be stripped if line endings such as \r\n prior to calling since
// scanning for these is a function of a higher layer such as bufio.Reader.ReadLine()
func (h *Header) Write(b []byte) (int, error) {
	if !bytes.Contains(b, []byte(`PROXY`)) {
		return 0, HeaderStringMalformed("no proxy prefix detected on header")
	}
	// ensure we don't have a \r\n\x00 (null byte at end)
	b = bytes.TrimSuffix(b, []byte("\r\n\x00"))
	// scan for:
	// PROXY <inet protocol> <client IP> <proxy IP> <client port> <proxy port>\r\n
	// spec: http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
	//

	// the entire text we are interested must be contained within 108 bytes
	// and we limit it as such. Only a properly formed
	// proxy string will pass through this process successfully.

	// we really only should be able to scan one line
	line := string(b)
	chunks := strings.Split(line, " ")
	if len(chunks) != 6 {
		// first case we do not read the underlying due to undefined data
		return len(b), HeaderStringMalformed(fmt.Sprintf("proxy line [%v] is malformed. expected len==6, got [%v]; after split; %v", line, len(chunks), chunks))
	}
	switch network := strings.ToLower(chunks[1]); network {
	case "tcp", "tcp6", "tcp4":
		h.client = &addr{network: network, address: chunks[2], port: chunks[4]}
		h.remote = &addr{network: network, address: chunks[3], port: chunks[5]}
		return len(b), nil
	}
	// this is the second case we don't read the underlying due to undefined data
	return len(b), net.UnknownNetworkError(fmt.Sprintf("%v", chunks[1]))
}

// LocalAddr ...
func (h *Header) LocalAddr() net.Addr { return h.client }

// RemoteAddr ...
func (h *Header) RemoteAddr() net.Addr { return h.remote }

func getIPPort(a net.Addr) (net.IP, int) {
	t, ok := a.(*net.TCPAddr)
	if !ok {
		return nil, 0
	}
	return t.IP, t.Port
}

// addr is a shortcut implementation to providing a net.Addr
type addr struct {
	network string
	address string
	port    string
}

func (a addr) Network() string { return a.network }
func (a addr) String() string {
	return net.JoinHostPort(a.address, a.port)
}

// NoProxyHeader is returned when the proxy writer code is called
// but there was no proxy header found.  It should be non-terminal
// and only used to continue processing a message as if no header was
// there.  Any additional failures will be handled accordingly downstream
type NoProxyHeader string

func (n NoProxyHeader) Error() string {
	return string(n)
}
