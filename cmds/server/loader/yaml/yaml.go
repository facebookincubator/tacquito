/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package yaml

import (
	"fmt"
	"io"
	"os"

	"github.com/facebookincubator/tacquito/cmds/server/config"

	"gopkg.in/yaml.v3"
)

// New returns a new yaml config unmarshaller
func New() *YAML {
	// TODO move channel to inotify
	return &YAML{config: make(chan config.ServerConfig, 1)}
}

// YAML loads all users from a given config filename
type YAML struct {
	config chan config.ServerConfig
}

// Load given a filename from disk, read all user data from it and unmarshal it
func (l *YAML) Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return fmt.Errorf("failed to read file: %v", err)
	}

	return l.Unmarshal(b)
}

// Unmarshal will decode bytes
func (l *YAML) Unmarshal(b []byte) error {
	var cfg config.ServerConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return fmt.Errorf("unable to unmarshal server config; %v", err)
	}
	if len(cfg.Secrets) < 1 {
		return fmt.Errorf("no secret providers were unmarshalled from config, cannot serve")
	}
	if len(cfg.Users) < 1 {
		return fmt.Errorf("no users were unmarshalled from config, cannot serve")
	}
	l.config <- cfg
	return nil
}

// Config must return a threadsafe copy of the underlying config.
func (l YAML) Config() chan config.ServerConfig {
	return l.config
}
