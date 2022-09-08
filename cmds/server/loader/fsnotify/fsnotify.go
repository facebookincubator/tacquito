/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package fsnotify

// Package fsnotify implements the inotify equivalent for the loader types using fsnotify.
// fsnotify should be used to detect changes in config files and hanlde dynamically loading them

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/facebookincubator/tacquito/cmds/server/config"
	"github.com/fsnotify/fsnotify"
)

type loader interface {
	Load(path string) error
	Config() chan config.ServerConfig
}

type loggerProvider interface {
	Infof(ctx context.Context, format string, args ...interface{})
	Errorf(ctx context.Context, format string, args ...interface{})
	Debugf(ctx context.Context, format string, args ...interface{})
}

// Watcher is a type that waches for config changes and processes config updates
// Watcher really just wraps other Loader types
type Watcher struct {
	loader
	loggerProvider
	ctx      context.Context
	watchman *fsnotify.Watcher
	config   chan config.ServerConfig
}

// New ...
func New(ctx context.Context, l loader, logger loggerProvider) *Watcher {
	return &Watcher{ctx: ctx, loader: l, loggerProvider: logger, config: make(chan config.ServerConfig, 1)}
}

// Load ...
func (w *Watcher) Load(path string) error {
	if err := w.loader.Load(path); err != nil {
		return fmt.Errorf("loader failed: %v", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("failed to create file watcher: %v", err)
	}
	if err := watcher.Add(filepath.Dir(path)); err != nil {
		return fmt.Errorf("failed watching config: %s", err)
	}
	w.watchman = watcher
	go w.watch(path)
	return nil
}

// watch ...
// You only want to call this ONCE
func (w *Watcher) watch(path string) {
	base := filepath.Base(path)
	w.Infof(w.ctx, "watching %s", base)
	ticker := time.NewTicker(time.Second * 1)
	var pending int
	for {
		select {
		case <-w.ctx.Done():
			w.Infof(w.ctx, "exiting watch loop for fsnotify; %v", w.ctx.Err())
			return
		case ev := <-w.watchman.Events:
			if ev.Op&fsnotify.Write == fsnotify.Write {
				// fsnotify monitors the entire directory of the config file
				// this check ignores things that aren't the config file
				// also ignores the .config.swp file to reduce noise
				if !strings.Contains(ev.String(), base) || filepath.Ext(ev.Name) == ".swp" {
					w.Debugf(w.ctx, "not the config file, skipping event %v", ev)
					ticker.Reset(time.Second * 1)
					continue
				}
				w.Debugf(w.ctx, "config file changed from event %v", ev)
				pending++ //track num of changes
			}
		case err := <-w.watchman.Errors:
			w.Errorf(w.ctx, "Error: ", err)
		case <-ticker.C:
			if pending > 0 {
				pending = 0
				w.Infof(w.ctx, "reloading config [%v]", path)
				if err := w.loader.Load(path); err != nil {
					w.Errorf(w.ctx, "bad config for path [%v]: %v", path, err)
				}
			}
		}
	}
}

// Config ...
func (w *Watcher) Config() chan config.ServerConfig {
	return w.loader.Config()
}
