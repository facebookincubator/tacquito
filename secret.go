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

// MultiSecretProvider is an optional extension to SecretProvider.  Implementations
// return all candidate secrets for a remote.  The server tries each in order on
// the first packet of a connection and uses the first that yields a parseable
// body, allowing hitless shared-secret rotation.  The Handler is per-source.
type MultiSecretProvider interface {
	GetSecrets(ctx context.Context, remote net.Addr) ([][]byte, Handler, error)
}
