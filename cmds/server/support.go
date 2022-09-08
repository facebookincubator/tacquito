/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package main

import (
	"context"
)

// The code here supports instantiation of types within the main func.
// We keep items here to avoid cluttering the main func.

// shh is a example implementation of a simple secret provider that fulfills the private getSecret interface
type shh struct{}

// GetSecret ...
func (s *shh) GetSecret(ctx context.Context, name, group string) ([]byte, error) {
	return []byte("cisco"), nil
}
