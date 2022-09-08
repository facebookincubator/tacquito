/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package json

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/facebookincubator/tacquito/cmds/server/config"
)

// New returns a new yaml config unmarshaller
func New() *JSON {
	// TODO move channel to inotify
	return &JSON{config: make(chan config.ServerConfig, 1)}
}

// JSON loads all users from a given config filename
type JSON struct {
	config.ServerConfig
	config chan config.ServerConfig
}

// Load given a filename from disk, read all user data from it and unmarshal it
func (l *JSON) Load(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	b, err := io.ReadAll(f)
	if err != nil {
		return err
	}
	return l.Unmarshal(b)
}

// Unmarshal will decode bytes
func (l *JSON) Unmarshal(b []byte) error {
	if err := json.Unmarshal(b, &l.ServerConfig); err != nil {
		return fmt.Errorf("unable to unmarshal server config; %v", err)
	}
	if len(l.ServerConfig.Secrets) < 1 {
		return fmt.Errorf("no secret providers were unmarshalled from config, cannot serve")
	}
	if len(l.ServerConfig.Users) < 1 {
		return fmt.Errorf("no users were unmarshalled from config, cannot serve")
	}
	l.config <- l.ServerConfig
	return nil
}

// Config must return a threadsafe copy of the underlying config.
func (l JSON) Config() chan config.ServerConfig {
	return l.config
}
