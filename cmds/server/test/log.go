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
	// Record provides a structed log interface for systems that need a record based format
	Record(ctx context.Context, r map[string]string, obscure ...string)
}

// NewDefaultLogger provides a basic logger if one is not provided
// levels: 10 error, 20 info, 30 debug.  fatal has no level
func NewDefaultLogger(level int) *DefaultLogger {
	return &DefaultLogger{
		level:       level,
		ErrorLogger: log.New(os.Stderr, "ERROR: ", log.Ldate|log.Ltime|log.Llongfile),
		InfoLogger:  log.New(os.Stderr, "INFO: ", log.Ldate|log.Ltime|log.Llongfile),
		DebugLogger: log.New(os.Stderr, "DEBUG: ", log.Ldate|log.Ltime|log.Llongfile),
	}
}

// DefaultLogger ...
type DefaultLogger struct {
	// log level to use
	level int
	// ErrorLogger is Level Error Logger
	ErrorLogger *log.Logger
	// InfoLogger is Level Info Logger
	InfoLogger *log.Logger
	// DebugLogger is a Level Debug Logger
	DebugLogger *log.Logger
}

// Record provides a log hook for record based log formats.  errors will be caught and logged to errorf
func (d DefaultLogger) Record(ctx context.Context, r map[string]string, obscure ...string) {}

// Errorf ...
func (d DefaultLogger) Errorf(ctx context.Context, format string, args ...interface{}) {
	if d.level >= 10 {
		d.ErrorLogger.Output(2, fmt.Sprintf(format, args...))
	}
}

// Infof ...
func (d DefaultLogger) Infof(ctx context.Context, format string, args ...interface{}) {
	if d.level >= 20 {
		d.InfoLogger.Output(2, fmt.Sprintf(format, args...))
	}
}

// Debugf ...
func (d DefaultLogger) Debugf(ctx context.Context, format string, args ...interface{}) {
	if d.level >= 30 {
		d.DebugLogger.Output(2, fmt.Sprintf(format, args...))
	}
}
