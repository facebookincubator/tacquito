/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"context"
	"net"
)

// SecretProvider is responsible for secret selection for incoming client connections
// It provides configuration items for the server to process any connections that originate
// on a given net.Conn.  Only the RemoteAddr is provided to make this determination.
type SecretProvider interface {
	Get(ctx context.Context, remote net.Addr) ([]byte, Handler, error)
}
