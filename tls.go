package tacquito

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"time"
)

// tlsDeadlineListener wraps a TLS listener to implement DeadlineListener
type TLSDeadlineListener struct {
	net.Listener
	tcpListener *net.TCPListener
}

func NewTLSListener(l net.Listener, config *tls.Config) (*TLSDeadlineListener, error) {
	if config == nil {
		return nil, errors.New("TLS config cannot be nil")
	}

	// Get the underlying TCP listener
	tcpListener, ok := l.(*net.TCPListener)
	if !ok {
		return nil, errors.New("listener must be a TCP listener for TLS support")
	}

	// Create a TLS listener
	tlsListener := tls.NewListener(tcpListener, config)

	// Wrap the TLS listener to implement DeadlineListener
	return &TLSDeadlineListener{
		Listener:    tlsListener,
		tcpListener: tcpListener,
	}, nil
}

// SetDeadline implements DeadlineListener interface
func (l *TLSDeadlineListener) SetDeadline(t time.Time) error {
	return l.tcpListener.SetDeadline(t)
}

// GenTLSConfig creates a TLS configuration for a TLS server
func GenTLSConfig(certFile, keyFile, CAFile string, requireMutualAuth bool) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: tls.VersionTLS13,            // Require TLS 1.3 as per the IETF draft
		ClientAuth: tls.VerifyClientCertIfGiven, // Mutual authentication is optional
	}

	if certFile == "" || keyFile == "" {
		return nil, errors.New("TLS is enabled but certificate or key file is not provided")
	}

	// Load server certificate and key
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	config.Certificates = []tls.Certificate{cert}

	// Configure client certificate verification if CA file is provided
	if CAFile != "" {
		data, err := os.ReadFile(CAFile)
		if err != nil {
			return nil, err
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(data) {
			return nil, errors.New("failed to append CA certificates")
		}
		config.ClientCAs = certPool
	}

	if requireMutualAuth {
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}

	return config, nil
}

// createTLSConfig creates a TLS configuration based on the provided command-line flags
func GenClientTLSConfig(serverName, certFile, keyFile, CAFile string, skipVerification bool) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion:         tls.VersionTLS13, // Require TLS 1.3 as per the IETF draft
		ServerName:         serverName,
		InsecureSkipVerify: skipVerification,
	}

	// Client certificates are optional - only load them for mutual TLS when both are provided
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, err
		}
		config.Certificates = []tls.Certificate{cert}
	}

	// Set RootCAs for server certificate verification if CA file is provided
	if CAFile != "" {
		data, err := os.ReadFile(CAFile)
		if err != nil {
			return nil, err
		}
		certPool := x509.NewCertPool()
		if !certPool.AppendCertsFromPEM(data) {
			return nil, errors.New("failed to append CA certificates")
		}
		config.RootCAs = certPool
	}

	return config, nil
}
