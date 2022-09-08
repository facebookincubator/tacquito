/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"context"
	"fmt"
	"log"
	"os"
)

// loggerProvider provides the logging implementation
type loggerProvider interface {
	Infof(ctx context.Context, format string, args ...interface{})
	Errorf(ctx context.Context, format string, args ...interface{})
	Debugf(ctx context.Context, format string, args ...interface{})
}

// newDefaultLogger provides a basic logger if one is not provided
// levels: 10 error, 20 info, 30 debug.  fatal has no level
func newDefaultLogger(level int) *defaultLogger {
	return &defaultLogger{
		level:       level,
		ErrorLogger: log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Llongfile),
		InfoLogger:  log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Llongfile),
		DebugLogger: log.New(os.Stderr, "DEBUG: ", log.Ldate|log.Ltime|log.Llongfile),
	}
}

// defaultLogger ...
type defaultLogger struct {
	// log level to use
	level int
	// ErrorLogger is Level Error Logger
	ErrorLogger *log.Logger
	// InfoLogger is Level Info Logger
	InfoLogger *log.Logger
	// DebugLogger is a Level Debug Logger
	DebugLogger *log.Logger
}

// Errorf ...
func (d defaultLogger) Errorf(ctx context.Context, format string, args ...interface{}) {
	if d.level >= 10 {
		d.ErrorLogger.Output(2, fmt.Sprintf(format, args...))
	}
}

// Infof ...
func (d defaultLogger) Infof(ctx context.Context, format string, args ...interface{}) {
	if d.level >= 20 {
		d.InfoLogger.Output(2, fmt.Sprintf(format, args...))
	}
}

// Debugf ...
func (d defaultLogger) Debugf(ctx context.Context, format string, args ...interface{}) {
	if d.level >= 30 {
		d.DebugLogger.Output(2, fmt.Sprintf(format, args...))
	}
}
