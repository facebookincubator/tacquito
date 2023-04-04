/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package handlers

import (
	"context"

	tq "github.com/facebookincubator/tacquito"
)

// loggerProvider provides the logging implementation
type loggerProvider interface {
	Infof(ctx context.Context, format string, args ...interface{})
	Errorf(ctx context.Context, format string, args ...interface{})
	Debugf(ctx context.Context, format string, args ...interface{})
	Record(ctx context.Context, r map[string]string, obscure ...string)
	Set(ctx context.Context, fields map[string]string, keys ...tq.ContextKey) context.Context
}
