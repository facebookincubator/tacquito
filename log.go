/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import "context"

// loggerProvider provides the logging implementation
type loggerProvider interface {
	Infof(ctx context.Context, format string, args ...any)
	Errorf(ctx context.Context, format string, args ...any)
	Debugf(ctx context.Context, format string, args ...any)
	// Record provides a structed log interface for systems that need a record based format
	Record(ctx context.Context, r map[string]string, obscure ...string)
}
