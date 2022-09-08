/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package main

import (
	"context"
	"fmt"
	"log"
	"os"
)

// newDefaultLogger provides a basic logger if one is not provided
// levels: 10 error, 20 info, 30 debug.  fatal has no level
func newDefaultLogger(level int) *defaultLogger {
	base := log.New(os.Stderr, "", 0)
	meta := log.Ldate | log.Ltime | log.Llongfile
	return &defaultLogger{
		level:       level,
		ErrorLogger: log.New(base.Writer(), "ERROR: ", meta),
		InfoLogger:  log.New(base.Writer(), "INFO: ", meta),
		DebugLogger: log.New(base.Writer(), "DEBUG: ", meta),
		FatalLogger: log.New(base.Writer(), "FATAL: ", meta),
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
	// FatalLogger is a Level Fatal Logger
	FatalLogger *log.Logger
}

// Record provides a log hook for record based log formats.  errors will be caught and logged to errorf
func (d defaultLogger) Record(ctx context.Context, r map[string]string, obscure ...string) {
	// hide fields as needed
	for _, key := range obscure {
		if _, ok := r[key]; ok {
			r[key] = "<obscured>"
		}
	}
	// do you own thing here
	d.Debugf(ctx, "%v", r)
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

// Fatalf ...
func (d defaultLogger) Fatalf(ctx context.Context, format string, args ...interface{}) {
	d.FatalLogger.Output(2, fmt.Sprintf(format, args...))
}
