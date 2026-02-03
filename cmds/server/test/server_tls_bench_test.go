/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
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

// GenerateTLSCertificate is part of the public API for this package
// can be overridden for other functions (such as the generateOptimizedTLSCertificate)
var GenerateTLSCertificate = generateTLSCertificate

// GenerateTLSCertificate generates a temporary TLS certificate and key in the given directory
// this can be utilized by the test to create TLS test specific config
func generateTLSCertificate(testDir string) (certFile, keyFile string, tlsConfig *tls.Config, err error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", nil, err
	}

	// Create certificate template
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
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.IPv6loopback, net.ParseIP("::1")},
		DNSNames:              []string{"localhost"},
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

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return "", "", nil, err
	}

	err = pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privKeyBytes})
	if err != nil {
		return "", "", nil, err
	}

	// Load certificate and create TLS config
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return "", "", nil, err
	}

	tlsConfig = &tls.Config{
		Certificates:       []tls.Certificate{cert},
		InsecureSkipVerify: true, // For test purposes
	}

	return certFile, keyFile, tlsConfig, nil
}

/* Base line results
goos: linux
goarch: amd64
pkg: github.com/facebookincubator/tacquito/cmds/server/test
cpu: Intel Core Processor (Broadwell)
BenchmarkPacketExchangeAsciiLoginUsingSharedClientTLS-72              44          73866034 ns/op           35767 B/op        454 allocs/op
BenchmarkPacketExchangeAsciiLoginUsingNewClientTLS-72                 43          78560658 ns/op          139176 B/op       1230 allocs/op
PASS
*/

// BenchmarkPacketExchangeAsciiLoginUsingSharedClientTLS will test the full ascii login flow
// using a single TLS client instance
func BenchmarkPacketExchangeAsciiLoginUsingSharedClientTLS(b *testing.B) {
	testDir := b.TempDir()
	_, _, serverTLSConfig, err := GenerateTLSCertificate(testDir)
	assert.NoError(b, err)

	logger := log.New(0, io.Discard) // no logs
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

	// Client TLS config (with insecure skip verify for test certificates)
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	c, err := tq.NewClient(tq.SetClientTLSDialer("tcp6", listener.Addr().String(), clientTLSConfig))
	assert.NoError(b, err)
	defer c.Close()

	test := ASCIILoginFullFlow()
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		for _, s := range test.Seq {
			c.Send(s.Packet)
		}
	}
}

// BenchmarkPacketExchangeAsciiLoginUsingNewClientTLS will test the full ascii login flow
// using a new TLS client instance each loop
func BenchmarkPacketExchangeAsciiLoginUsingNewClientTLS(b *testing.B) {
	testDir := b.TempDir()
	_, _, serverTLSConfig, err := GenerateTLSCertificate(testDir)
	assert.NoError(b, err)

	logger := log.New(0, io.Discard) // no logs
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

	// Client TLS config (with insecure skip verify for test certificates)
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	test := ASCIILoginFullFlow()
	for n := 0; n < b.N; n++ {
		c, err := tq.NewClient(tq.SetClientTLSDialer("tcp6", listener.Addr().String(), clientTLSConfig))
		assert.NoError(b, err)
		for _, s := range test.Seq {
			c.Send(s.Packet)
		}
		c.Close()
	}
}
