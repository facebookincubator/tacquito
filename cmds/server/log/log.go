/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package log

import (
	"context"
	"fmt"
	"io"
	"log"

	tq "github.com/facebookincubator/tacquito"
)

// New provides a basic logger if one is not provided
// levels: 10 error, 20 info, 30 debug.  fatal has no level
func New(level int, w io.Writer) *Logger {
	base := log.New(w, "", 0)
	meta := log.Ldate | log.Ltime | log.Llongfile
	return &Logger{
		level:       level,
		errorLogger: log.New(base.Writer(), "ERROR: ", meta),
		infoLogger:  log.New(base.Writer(), "INFO: ", meta),
		debugLogger: log.New(base.Writer(), "DEBUG: ", meta),
		fatalLogger: log.New(base.Writer(), "FATAL: ", meta),
	}
}

// Logger ...
type Logger struct {
	// log level to use
	level int
	// errorLogger is Level Error Logger
	errorLogger *log.Logger
	// infoLogger is Level Info Logger
	infoLogger *log.Logger
	// debugLogger is a Level Debug Logger
	debugLogger *log.Logger
	// fatalLogger is a Level Fatal Logger
	fatalLogger *log.Logger
}

// Record provides a log hook for record based log formats.  errors will be caught and logged to errorf
func (d Logger) Record(ctx context.Context, r map[string]string, obscure ...string) {
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
func (d Logger) Errorf(ctx context.Context, format string, args ...interface{}) {
	if d.level >= 10 {
		d.errorLogger.Output(2, fmt.Sprintf(format, args...))
	}
}

// Infof ...
func (d Logger) Infof(ctx context.Context, format string, args ...interface{}) {
	if d.level >= 20 {
		d.infoLogger.Output(2, fmt.Sprintf(format, args...))
	}
}

// Debugf ...
func (d Logger) Debugf(ctx context.Context, format string, args ...interface{}) {
	if d.level >= 30 {
		d.debugLogger.Output(2, fmt.Sprintf(format, args...))
	}
}

// Fatalf ...
func (d Logger) Fatalf(ctx context.Context, format string, args ...interface{}) {
	d.fatalLogger.Output(2, fmt.Sprintf(format, args...))
}

// Set will extract keys from the request, and save them to the
// logger's context
func (d Logger) Set(ctx context.Context, fields map[string]string, keys ...tq.ContextKey) context.Context {
	// set fields here if needed
	// for _, key := range keys {
	// 	ctx = context.WithValue(ctx, key, fields[string(key)])
	// }
	return ctx
}
