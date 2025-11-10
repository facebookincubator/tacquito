/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResolvePath tests the resolvePath function with various path inputs
func TestResolvePath(t *testing.T) {
	// We need to create some temporary state to test resolvePath with
	tempDir, err := os.MkdirTemp("", "tls_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	testFile := filepath.Join(tempDir, "test.cert")
	err = os.WriteFile(testFile, []byte("test cert content"), 0644)
	require.NoError(t, err)

	subDir := filepath.Join(tempDir, "subdir")
	err = os.MkdirAll(subDir, 0755)
	require.NoError(t, err)

	subFile := filepath.Join(subDir, "sub.cert")
	err = os.WriteFile(subFile, []byte("sub cert content"), 0644)
	require.NoError(t, err)

	tests := []struct {
		name      string
		path      string
		fileType  string
		shouldErr bool
		errMsg    string
		setup     func() string // function to set up path relative to tempDir
	}{
		{
			name:     "empty path",
			path:     "",
			fileType: "certificate",
		},
		{
			name:     "existing absolute path",
			fileType: "certificate",
			setup: func() string {
				return testFile
			},
		},
		{
			name:     "existing relative path",
			fileType: "certificate",
			setup: func() string {
				// Change to tempDir and use relative path
				original, _ := os.Getwd()
				os.Chdir(tempDir)
				t.Cleanup(func() { os.Chdir(original) })
				return "test.cert"
			},
		},
		{
			name:      "non-existing file",
			path:      "/non/existent/file.cert",
			fileType:  "certificate",
			shouldErr: true,
			errMsg:    "certificate file does not exist",
		},
		{
			name:      "non-existent file from relative path",
			fileType:  "certificate",
			shouldErr: true,
			errMsg:    "certificate file does not exist",
			setup: func() string {
				return filepath.Join(tempDir, "nonexistent.cert")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := tt.path
			if tt.setup != nil {
				path = tt.setup()
			}

			result, err := resolvePath(path, tt.fileType)

			if tt.shouldErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			assert.NoError(t, err)

			if path == "" {
				assert.Equal(t, "", result)
			} else {
				// Result should be absolute path
				assert.True(t, filepath.IsAbs(result))

				// If file should exist, verify it does
				if !strings.Contains(tt.name, "non-existing") && !strings.Contains(tt.name, "nonexistent") {
					_, statErr := os.Stat(result)
					assert.NoError(t, statErr, "resolved file should exist")
				}
			}
		})
	}
}

func TestParsedTLSConfigValidate(t *testing.T) {
	tempDir, err := os.MkdirTemp("", "tls_config_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")
	caFile := filepath.Join(tempDir, "ca.pem")

	for _, file := range []string{certFile, keyFile, caFile} {
		err = os.WriteFile(file, []byte("dummy content"), 0644)
		require.NoError(t, err)
	}

	tests := []struct {
		name      string
		config    ParsedTLSConfig
		shouldErr bool
		errMsg    string
		setup     func(*ParsedTLSConfig)
	}{
		{
			name: "valid absolute paths",
			config: ParsedTLSConfig{
				CertFile: certFile,
				KeyFile:  keyFile,
				CAFile:   caFile,
			},
		},
		{
			name: "valid relative paths",
			config: ParsedTLSConfig{
				CertFile: "./cert.pem",
				KeyFile:  "./key.pem",
				CAFile:   "./ca.pem",
			},
			setup: func(config *ParsedTLSConfig) {
				// Change to temp directory for relative paths to work
				original, _ := os.Getwd()
				os.Chdir(tempDir)
				t.Cleanup(func() { os.Chdir(original) })
			},
		},
		{
			name: "cert without key",
			config: ParsedTLSConfig{
				CertFile: certFile,
				// KeyFile is empty
			},
			shouldErr: true,
			errMsg:    "TLS key file must be specified when certificate file is provided",
		},
		{
			name: "key without cert",
			config: ParsedTLSConfig{
				KeyFile: keyFile,
				// CertFile is empty
			},
			shouldErr: true,
			errMsg:    "TLS certificate file must be specified when key file is provided",
		},
		{
			name: "non-existent cert file",
			config: ParsedTLSConfig{
				CertFile: "/non/existent/cert.pem",
				KeyFile:  keyFile,
			},
			shouldErr: true,
			errMsg:    "TLS certificate file does not exist",
		},
		{
			name: "non-existent key file",
			config: ParsedTLSConfig{
				CertFile: certFile,
				KeyFile:  "/non/existent/key.pem",
			},
			shouldErr: true,
			errMsg:    "TLS key file does not exist",
		},
		{
			name: "non-existent CA file",
			config: ParsedTLSConfig{
				CertFile: certFile,
				KeyFile:  keyFile,
				CAFile:   "/non/existent/ca.pem",
			},
			shouldErr: true,
			errMsg:    "TLS CA file does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := tt.config

			if tt.setup != nil {
				tt.setup(&config)
			}

			err := config.Validate()

			if tt.shouldErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			assert.NoError(t, err)

			// Verify that paths have been resolved to absolute paths
			if config.CertFile != "" {
				assert.True(t, filepath.IsAbs(config.CertFile))
			}
			if config.KeyFile != "" {
				assert.True(t, filepath.IsAbs(config.KeyFile))
			}
			if config.CAFile != "" {
				assert.True(t, filepath.IsAbs(config.CAFile))
			}
		})
	}
}

func TestLoadTLSConfig(t *testing.T) {
	// Create temporary directory for test files
	tempDir, err := os.MkdirTemp("", "tls_config_load_test")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create test certificate files
	certFile := filepath.Join(tempDir, "server.crt")
	keyFile := filepath.Join(tempDir, "server.key")
	caFile := filepath.Join(tempDir, "ca.crt")

	for _, file := range []string{certFile, keyFile, caFile} {
		err = os.WriteFile(file, []byte("dummy cert content"), 0644)
		require.NoError(t, err)
	}

	tests := []struct {
		name         string
		configJSON   map[string]interface{}
		shouldErr    bool
		errMsg       string
		validateFunc func(*testing.T, *ParsedTLSConfig)
	}{
		{
			name: "valid config with absolute paths",
			configJSON: map[string]interface{}{
				"cert_file":            certFile,
				"key_file":             keyFile,
				"ca_file":              caFile,
				"server_name":          "test",
				"insecure_skip_verify": false,
			},
			validateFunc: func(t *testing.T, config *ParsedTLSConfig) {
				assert.Equal(t, certFile, config.CertFile)
				assert.Equal(t, keyFile, config.KeyFile)
				assert.Equal(t, caFile, config.CAFile)
				assert.Equal(t, "test", config.ServerName)
				assert.False(t, config.InsecureSkipVerify)
			},
		},
		{
			name: "config with relative paths",
			configJSON: map[string]interface{}{
				"cert_file": "./server.crt",
				"key_file":  "./server.key",
				"ca_file":   "./ca.crt",
			},
			validateFunc: func(t *testing.T, config *ParsedTLSConfig) {
				// Paths should be resolved to absolute paths
				assert.True(t, filepath.IsAbs(config.CertFile))
				assert.True(t, filepath.IsAbs(config.KeyFile))
				assert.True(t, filepath.IsAbs(config.CAFile))

				// Files should exist
				for _, path := range []string{config.CertFile, config.KeyFile, config.CAFile} {
					_, err := os.Stat(path)
					assert.NoError(t, err)
				}
			},
		},
		{
			name: "cert without key",
			configJSON: map[string]interface{}{
				"cert_file": certFile,
			},
			shouldErr: true,
			errMsg:    "TLS key file must be specified when certificate file is provided",
		},
		{
			name: "non-existent files",
			configJSON: map[string]interface{}{
				"cert_file": "/non/existent/cert.pem",
				"key_file":  "/non/existent/key.pem",
			},
			shouldErr: true,
			errMsg:    "TLS certificate file does not exist",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configFile := filepath.Join(tempDir, fmt.Sprintf("config_%s.json", strings.ReplaceAll(tt.name, " ", "_")))

			// For relative paths test, change to temp directory
			if tt.name == "config with relative paths" {
				original, _ := os.Getwd()
				os.Chdir(tempDir)
				defer os.Chdir(original)
			}

			configData, err := json.Marshal(tt.configJSON)
			require.NoError(t, err)

			err = os.WriteFile(configFile, configData, 0644)
			require.NoError(t, err)

			// Load configuration
			config, err := LoadTLSConfig(configFile)

			if tt.shouldErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, config)

			if tt.validateFunc != nil {
				tt.validateFunc(t, config)
			}
		})
	}
}
