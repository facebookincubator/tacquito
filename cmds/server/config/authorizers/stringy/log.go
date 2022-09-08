/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package stringy

import (
	"context"
	"fmt"
	"log"
	"os"
)

// NewDefaultLogger provides a basic logger for tests
func NewDefaultLogger() *DefaultLogger {
	return &DefaultLogger{
		ErrorLogger: log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Llongfile),
		InfoLogger:  log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Llongfile),
		DebugLogger: log.New(os.Stderr, "DEBUG: ", log.Ldate|log.Ltime|log.Llongfile),
	}
}

// DefaultLogger ...
type DefaultLogger struct {
	// ErrorLogger is Level Error Logger
	ErrorLogger *log.Logger
	// InfoLogger is Level Info Logger
	InfoLogger *log.Logger
	// DebugLogger is a Level Debug Logger
	DebugLogger *log.Logger
}

// Errorf ...
func (d DefaultLogger) Errorf(ctx context.Context, format string, args ...interface{}) {
	d.ErrorLogger.Output(2, fmt.Sprintf(format, args...))
}

// Infof ...
func (d DefaultLogger) Infof(ctx context.Context, format string, args ...interface{}) {
	d.InfoLogger.Output(2, fmt.Sprintf(format, args...))
}

// Debugf ...
func (d DefaultLogger) Debugf(ctx context.Context, format string, args ...interface{}) {
	d.DebugLogger.Output(2, fmt.Sprintf(format, args...))
}
