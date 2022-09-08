/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package prefix

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"
)

// loggerProvider provides the logging implementation
type loggerProvider interface {
	Infof(ctx context.Context, format string, args ...interface{})
	Errorf(ctx context.Context, format string, args ...interface{})
	Debugf(ctx context.Context, format string, args ...interface{})
	Record(ctx context.Context, r map[string]string, obscure ...string)
}

// ProviderOption is the setter type for Provider
type ProviderOption func(p *Provider)

// SetPrefixSecret will set a secret config for a given prefix source
// this could be a range that clients call in from or from specific hosts
func SetPrefixSecret(config secretConfig, prefixes ...string) ProviderOption {
	return func(p *Provider) {
		for _, prefix := range prefixes {
			_, ipnet, err := net.ParseCIDR(prefix)
			if err != nil {
				continue
			}
			p.secrets[ipnet.String()] = config
		}
	}
}

// SetLoggerProvider will set a logger to use
func SetLoggerProvider(l loggerProvider) ProviderOption {
	return func(p *Provider) {
		p.loggerProvider = l
	}
}

// New creates new config sources based on users, groups and services
func New(l loggerProvider, opts ...ProviderOption) *Provider {
	s := &Provider{
		loggerProvider: l,
		secrets:        make(map[string]secretConfig),
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Provider ...
type Provider struct {
	loggerProvider
	secrets map[string]secretConfig
}

// New returns a scoped Provider for a given set of users.
func (p *Provider) New(ctx context.Context, provider config.SecretConfig, handler tq.Handler, secret func(context.Context, string) ([]byte, error)) tq.SecretProvider {
	var prefixes []string
	raw := provider.Options["prefixes"]
	if err := json.Unmarshal([]byte(raw), &prefixes); err != nil {
		p.Errorf(ctx, "missing prefixes key in options for prefix based secret provider [%v]", provider.Name)
		return nil
	}
	if len(prefixes) == 0 {
		p.Errorf(ctx, "no prefixes provided for prefix based secret provider [%v]", provider.Name)
		return nil
	}
	scopedConfig := secretConfig{
		secret:  secret,
		Handler: handler,
	}
	return New(
		p.loggerProvider,
		SetPrefixSecret(scopedConfig, prefixes...),
	)
}

// Get returns a tq SecretProvider interface and or error
func (p *Provider) Get(ctx context.Context, remote net.Addr) ([]byte, tq.Handler, error) {
	addr, ok := remote.(*net.TCPAddr)
	if !ok {
		return nil, nil, fmt.Errorf("unable to assert [%v] is net.TCPAddr", remote)
	}
	for cidr, c := range p.secrets {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			p.Errorf(ctx, "error parsing ip from SecretProvider: %v", err)
			continue
		}
		if ipNet.Contains(addr.IP) {
			p.Debugf(ctx, "prefix secret provider matches remote [%v] against prefix [%v]", addr.IP.String(), cidr)
			secret, err := c.secret(ctx, addr.IP.String())
			return secret, c, err
		}
	}
	return nil, nil, fmt.Errorf("no matching prefix secret provider found")
}

// secretConfig holds the secret config needed for the SecretProvider
type secretConfig struct {
	// Secret is applied when performing crypt/obfuscation ops
	secret func(context.Context, string) ([]byte, error)
	// Handler embeds our Handler interface scoped to this SecretConfig
	tq.Handler
}
