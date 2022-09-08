/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package dns

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"

	"github.com/prometheus/client_golang/prometheus"
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

// SetDNSSecret will set a secret config for a given hostname
func SetDNSSecret(config secretConfig, hosts ...string) ProviderOption {
	return func(p *Provider) {
		for _, h := range hosts {
			p.secrets[h] = config
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
	s := &Provider{loggerProvider: l, secrets: make(map[string]secretConfig)}
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
	var hosts []string
	err := json.Unmarshal([]byte(provider.Options["hosts"]), &hosts)
	if err != nil {
		p.Errorf(ctx, "unable to unmarshal key [hosts] on dns based secret provider [%v]; %v", provider.Name, err)
		return nil
	}
	if len(hosts) == 0 {
		p.Errorf(ctx, "no host provided for dns based secret provider [%v]", provider.Name)
		return nil
	}

	scopedConfig := secretConfig{
		secret:  secret,
		Handler: handler,
	}

	return New(
		p.loggerProvider,
		SetDNSSecret(scopedConfig, hosts...),
	)
}

// Get returns a tq SecretProvider interface and or error
func (p *Provider) Get(ctx context.Context, remote net.Addr) ([]byte, tq.Handler, error) {
	addr, ok := remote.(*net.TCPAddr)
	if !ok {
		return nil, nil, fmt.Errorf("unable to assert [%v] is net.TCPAddr", remote)
	}
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		ms := v * 1000 // make milliseconds
		dnsDurations.Observe(ms)
	}))
	names, err := net.LookupAddr(addr.IP.String())
	if err != nil {
		timer.ObserveDuration()
		dnsError.Inc()
		return nil, nil, err
	}
	timer.ObserveDuration()
	for _, name := range names {
		if c, ok := p.secrets[name]; ok {
			dnsGetMatch.Inc()
			p.Debugf(ctx, "dns secret provider matches remote [%v] against fqdn [%v]", addr.IP.String(), name)
			secret, err := c.secret(ctx, name)
			return secret, c, err
		}
	}
	return nil, nil, fmt.Errorf("no matching dns secret provider found for names %v, for remote [%v]", names, addr.IP.String())
}

// secretConfig holds the secret config needed for the SecretProvider
type secretConfig struct {
	// Secret is applied when performing crypt/obfuscation ops
	secret func(context.Context, string) ([]byte, error)
	// Handler embeds our Handler interface scoped to this SecretConfig
	tq.Handler
}
