package tacquito

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
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
		ClientAuth: tls.VerifyClientCertIfGiven, // Mutual authentication is optional to start with, but is highly recommended
	}

	if certFile == "" || keyFile == "" {
		return nil, errors.New("TLS is enabled but certificate or key file is not provided")
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	config.Certificates = []tls.Certificate{cert}

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
func GenClientTLSConfig(p *ParsedTLSConfig) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion:         tls.VersionTLS13, // Require TLS 1.3 as per the IETF draft
		ServerName:         p.ServerName,
		InsecureSkipVerify: p.InsecureSkipVerify, // false by default
	}

	if p.CertFile == "" || p.KeyFile == "" {
		return nil, errors.New("Client config: TLS is enabled but certificate or key file is not provided")
	}

	cert, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
	if err != nil {
		return nil, err
	}
	config.Certificates = []tls.Certificate{cert}

	if p.CAFile != "" {
		data, err := os.ReadFile(p.CAFile)
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

// TLSConfig represents the TLS configuration that can be loaded from a JSON file
// If a TLS config file is specified, TLS is automatically enabled
type ParsedTLSConfig struct {
	// Certificate files
	CertFile string `json:"cert_file"`
	KeyFile  string `json:"key_file"`
	CAFile   string `json:"ca_file"`

	// Server name for certificate validation
	ServerName string `json:"server_name"`

	// Skip certificate verification (not recommended for production)
	InsecureSkipVerify bool `json:"insecure_skip_verify"`
}

// LoadTLSConfig loads TLS configuration from a JSON file
func LoadTLSConfig(filename string) (*ParsedTLSConfig, error) {
	if filename == "" {
		return nil, fmt.Errorf("TLS config file path is empty")
	}

	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, fmt.Errorf("TLS config file does not exist: %s", filename)
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read TLS config file: %w", err)
	}

	var config ParsedTLSConfig
	err = json.Unmarshal(data, &config)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JSON TLS config: %w", err)
	}

	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid TLS config: %w", err)
	}

	return &config, nil
}

// Validate checks if the TLS configuration is valid
func (c *ParsedTLSConfig) Validate() error {
	var err error

	if c.CertFile, err = resolvePath(c.CertFile, "TLS certificate"); err != nil {
		return err
	}

	if c.KeyFile, err = resolvePath(c.KeyFile, "TLS key"); err != nil {
		return err
	}

	if c.CAFile, err = resolvePath(c.CAFile, "TLS CA"); err != nil {
		return err
	}

	// If client cert is specified, key must also be specified and vice versa
	if c.CertFile != "" && c.KeyFile == "" {
		return fmt.Errorf("TLS key file must be specified when certificate file is provided")
	}
	if c.KeyFile != "" && c.CertFile == "" {
		return fmt.Errorf("TLS certificate file must be specified when key file is provided")
	}

	return nil
}

// resolvePath converts relative paths to absolute paths and checks if the file exists
// Returns the absolute path and an error if the file doesn't exist or path conversion fails
func resolvePath(path, fileType string) (string, error) {
	if path == "" {
		return "", nil
	}

	// Convert to absolute path (handles relative paths like ./file or ../file)
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("failed to convert %s file path '%s' to absolute path: %w", fileType, path, err)
	}

	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return "", fmt.Errorf("%s file does not exist: %s", fileType, absPath)
	}

	return absPath, nil
}
