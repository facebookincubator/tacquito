/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/log"

	"github.com/stretchr/testify/assert"
)

// generateOptimizedTLSCertificate generates the TLS config that is performance focused
// and makes the tradeoff of security for performance
func generateOptimizedTLSCertificate(testDir string) (certFile, keyFile string, tlsConfig *tls.Config, err error) {
	// Use ECDSA P-256 (fastest secure curve)
	// ref: https://www.ssl.com/article/comparing-ecdsa-vs-rsa-a-simple-guide/
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", nil, err
	}

	// Absolute minimal certificate for maximum parsing speed
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Corp"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"Test City"},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour), // Very short validity
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("::1")},
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return "", "", nil, err
	}

	// Write certificate to file
	certFile = filepath.Join(testDir, "cert.pem")
	certOut, err := os.Create(certFile)
	if err != nil {
		return "", "", nil, err
	}
	defer certOut.Close()

	err = pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err != nil {
		return "", "", nil, err
	}

	// Write private key to file
	keyFile = filepath.Join(testDir, "key.pem")
	keyOut, err := os.Create(keyFile)
	if err != nil {
		return "", "", nil, err
	}
	defer keyOut.Close()

	privKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", nil, err
	}

	err = pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		return "", "", nil, err
	}

	// Load certificate and create ultra-fast TLS config
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return "", "", nil, err
	}

	tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},

		// Performance optimizations targeting the CPU profile bottlenecks:
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,

		// Force fastest cipher suite to avoid ML-KEM overhead
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256, // Fastest: AES-128-GCM with SHA256
		},

		InsecureSkipVerify:          true,                               // Skip cert verification
		SessionTicketsDisabled:      false,                              // Enable session tickets
		ClientSessionCache:          tls.NewLRUClientSessionCache(1000), // Large session cache
		DynamicRecordSizingDisabled: true,                               // Fixed record sizes

		// Disable all unnecessary features
		// ALPN is a TLS extension that allows clients to negotiate the use of a specific application protocol
		// No ALPN because client and server are both tacacs here with a well known version
		// no need for any negotiation code
		NextProtos: nil,
		ServerName: "", // No SNI
		// tls.RenegotiateNever disables TLS renegotiation which that allows either the client or server to initiate a new handshake over an existing TLS connection to
		// change connection parameters
		// Disabled purely for performance reasons
		Renegotiation: tls.RenegotiateNever, // Never renegotiate
		KeyLogWriter:  nil,                  // No key logging
	}

	return certFile, keyFile, tlsConfig, nil
}

// BenchmarkUltraFastTLS tests TLS with maximum performance optimizations
// Based on CPU profile analysis showing ML-KEM and syscall overhead
func BenchmarkPacketExchangeAsciiLoginUsingSharedClientTLSOptimized(b *testing.B) {
	testDir := b.TempDir()
	_, _, serverTLSConfig, err := generateOptimizedTLSCertificate(testDir)
	assert.NoError(b, err)

	logger := log.New(0, io.Discard)
	ctx := context.Background()
	sp, err := MockSecretProvider(ctx, logger, "testdata/test_config.yaml")
	assert.NoError(b, err)

	// Create TLS listener
	listener, err := net.Listen("tcp6", "[::1]:0")
	assert.NoError(b, err)
	tlsListener, err := tq.NewTLSListener(listener, serverTLSConfig)
	assert.NoError(b, err)

	s := tq.NewServer(logger, sp, tq.SetUseTLS(true))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := s.Serve(ctx, tlsListener); err != nil {
			assert.NoError(b, err)
		}
	}()

	clientTLSConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true,

		// Disable post-quantum crypto (ML-KEM was 8%+ of CPU time)
		// Force fastest cipher suite only
		CipherSuites: []uint16{
			tls.TLS_AES_128_GCM_SHA256, // Fastest authenticated encryption according to benchmarks
		},

		// Maximize session reuse to avoid handshakes
		SessionTicketsDisabled: false,
		ClientSessionCache:     tls.NewLRUClientSessionCache(1000),

		// Disable unnecessary features
		NextProtos:                  nil,                  // No ALPN
		ServerName:                  "",                   // No SNI
		Renegotiation:               tls.RenegotiateNever, // Never renegotiate
		DynamicRecordSizingDisabled: true,                 // Disable adaptive record sizes

		// Minimize handshake data
		KeyLogWriter: nil,
	}

	// Create shared client to leverage session resumption
	c, err := tq.NewClient(tq.SetClientTLSDialer("tcp6", listener.Addr().String(), clientTLSConfig))
	assert.NoError(b, err)
	defer c.Close()

	test := ASCIILoginFullFlow()
	b.ReportAllocs()
	b.ResetTimer() // Don't count setup time

	for n := 0; n < b.N; n++ {
		for _, s := range test.Seq {
			_, err := c.Send(s.Packet)
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

// BenchmarkPureTLSHandshake tests ONLY TLS handshake performance without any application logic
// This eliminates bcrypt and authentication overhead completely
func BenchmarkPureTLSHandshakeOptimized(b *testing.B) {
	testDir := b.TempDir()
	_, _, serverTLSConfig, err := generateOptimizedTLSCertificate(testDir)
	assert.NoError(b, err)

	// Start TLS server
	listener, err := net.Listen("tcp6", "[::1]:0")
	assert.NoError(b, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			// Upgrade to TLS and immediately close - just measure handshake
			tlsConn := tls.Server(conn, serverTLSConfig)
			if err := tlsConn.Handshake(); err != nil {
				b.Error(err)
				tlsConn.Close()
				return
			}
			tlsConn.Close()
		}
	}()

	clientTLSConfig := &tls.Config{
		MinVersion:                  tls.VersionTLS13,
		MaxVersion:                  tls.VersionTLS13,
		InsecureSkipVerify:          true,
		CipherSuites:                []uint16{tls.TLS_AES_128_GCM_SHA256},
		SessionTicketsDisabled:      false,
		ClientSessionCache:          tls.NewLRUClientSessionCache(1000),
		DynamicRecordSizingDisabled: true,
	}

	b.ReportAllocs()
	b.ResetTimer()

	// Test pure TLS handshake performance
	for n := 0; n < b.N; n++ {
		conn, err := tls.Dial("tcp6", listener.Addr().String(), clientTLSConfig)
		if err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}

// BenchmarkPureTLSHandshakeBaseline tests basic TLS handshake with default settings
func BenchmarkPureTLSHandshakeBaseline(b *testing.B) {
	testDir := b.TempDir()
	_, _, serverTLSConfig, err := GenerateTLSCertificate(testDir)
	assert.NoError(b, err)

	// Start TLS server
	listener, err := net.Listen("tcp6", "[::1]:0")
	assert.NoError(b, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}

			// Upgrade to TLS and immediately close
			tlsConn := tls.Server(conn, serverTLSConfig)
			if err := tlsConn.Handshake(); err != nil {
				b.Error(err)
				tlsConn.Close()
				return
			}
			tlsConn.Close()
		}
	}()

	// Basic client TLS config
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	b.ReportAllocs()
	b.ResetTimer()

	// Test basic TLS handshake performance
	for n := 0; n < b.N; n++ {
		conn, err := tls.Dial("tcp6", listener.Addr().String(), clientTLSConfig)
		if err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}

// BenchmarkPlainTCPConnection tests raw TCP connection for comparison baseline
func BenchmarkPlainTCPConnectionAgainstTLS(b *testing.B) {
	// Start plain TCP server
	listener, err := net.Listen("tcp6", "[::1]:0")
	assert.NoError(b, err)
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	b.ReportAllocs()
	b.ResetTimer()

	// Test raw TCP connection performance
	for n := 0; n < b.N; n++ {
		conn, err := net.Dial("tcp6", listener.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}
