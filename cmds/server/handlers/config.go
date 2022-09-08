/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package handlers

import (
	"github.com/facebookincubator/tacquito/cmds/server/config"
)

// configProvider provides access to user level AAA operations with a fallback for global
// All implementations must be compatible with a concurrent access model.  Non-threadsafe
// implementations are not recommended.

type configProvider interface {
	GetUser(user string) *config.AAA
}
