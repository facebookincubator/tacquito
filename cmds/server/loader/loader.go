/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package loader provides an injectable config loading mechanism.
package loader

import (
	"context"
	"fmt"
	"net"
	"sync"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"
)

// loggerProvider provides the logging implementation
type loggerProvider interface {
	Infof(ctx context.Context, format string, args ...interface{})
	Errorf(ctx context.Context, format string, args ...interface{})
	Debugf(ctx context.Context, format string, args ...interface{})
}

// keychainProvider will supply the pre-shard key for tacacs, ideally from secure storage
type keychainProvider interface {
	Add(k config.Keychain) func(context.Context, string) ([]byte, error)
}

// providerFactory creates scoped user config providers for each secret provider
type providerFactory interface {
	New(users map[string]*config.AAA) config.Provider
}

// secretProviderFactory provides a new tq.SecretProvider
type secretProviderFactory interface {
	New(ctx context.Context, sc config.SecretConfig, h tq.Handler, secret func(context.Context, string) ([]byte, error)) tq.SecretProvider
}

// handlerFactory provides new handler types
type handlerFactory interface {
	New(ctx context.Context, cp config.Provider, options map[string]string) tq.Handler
}

// authenticatorFactory provides new authenticator types
type authenticatorFactory interface {
	New(username string, options map[string]string) (tq.Handler, error)
}

// accounterFactory provides new accounter types
type accounterFactory interface {
	New(options map[string]string) tq.Handler
}

// authorizerFactory provides new authorizer types
type authorizerFactory interface {
	New(user config.User) (tq.Handler, error)
}

// localloader represents a config loader
type localloader interface {
	Load(path string) error
	unmarshaled
}

// unmarshaled represents a config unmarshaller that provides an unmarshalled config
type unmarshaled interface {
	Config() chan config.ServerConfig
}

// Option ...
type Option func(l *Loader)

// SetLoggerProvider will set a logger to use
func SetLoggerProvider(log loggerProvider) Option {
	return func(l *Loader) {
		l.loggerProvider = log
	}
}

// RegisterHandlerType ...
func RegisterHandlerType(t config.HandlerType, h handlerFactory) Option {
	return func(l *Loader) {
		l.handlerTypes[t] = h
	}
}

// SetKeychainProvider ..
func SetKeychainProvider(k keychainProvider) Option {
	return func(l *Loader) {
		l.keychainProvider = k
	}
}

// SetConfigProvider ..
func SetConfigProvider(c providerFactory) Option {
	return func(l *Loader) {
		l.configProvider = c
	}
}

// SetAuthorizerProvider ...
func SetAuthorizerProvider(a authorizerFactory) Option {
	return func(l *Loader) {
		l.authorizerProvider = a
	}
}

// RegisterSecretProviderType ...
func RegisterSecretProviderType(t config.ProviderType, sp secretProviderFactory) Option {
	return func(l *Loader) {
		l.providerTypes[t] = sp
	}
}

// RegisterAuthenticator ...
func RegisterAuthenticator(t config.AuthenticatorType, a authenticatorFactory) Option {
	return func(l *Loader) {
		l.authenticatorTypes[t] = a
	}
}

// RegisterAccounter ...
func RegisterAccounter(t config.AccounterType, a accounterFactory) Option {
	return func(l *Loader) {
		l.accounterTypes[t] = a
	}
}

// NewLocalConfig will create a new Loader that will take loader provided config and turn it into
// actionable server config types
func NewLocalConfig(ctx context.Context, path string, ll localloader, opts ...Option) (*Loader, error) {
	if err := ll.Load(path); err != nil {
		return nil, err
	}
	return NewLoader(ctx, ll, opts...)
}

// NewLoader ...
func NewLoader(ctx context.Context, l unmarshaled, opts ...Option) (*Loader, error) {
	wl := &Loader{
		ctx:                ctx,
		unmarshaled:        l,
		providerTypes:      make(map[config.ProviderType]secretProviderFactory),
		authenticatorTypes: make(map[config.AuthenticatorType]authenticatorFactory),
		accounterTypes:     make(map[config.AccounterType]accounterFactory),
		handlerTypes:       make(map[config.HandlerType]handlerFactory),
		query:              make(chan queryGet),
		warm:               make(chan struct{}),
	}
	for _, opt := range opts {
		opt(wl)
	}
	if wl.loggerProvider == nil {
		return nil, fmt.Errorf("please provide a logger")
	}
	if wl.keychainProvider == nil {
		return nil, fmt.Errorf("please provide a keychain provider")
	}
	if wl.configProvider == nil {
		return nil, fmt.Errorf("please provide a config provider")
	}
	if wl.authorizerProvider == nil {
		return nil, fmt.Errorf("please provide an authorizer provider")
	}
	go wl.updates()
	return wl, nil
}

// Loader will load in the config provided by loader.
type Loader struct {
	unmarshaled
	loggerProvider
	ctx                context.Context
	keychainProvider   keychainProvider
	configProvider     providerFactory
	authorizerProvider authorizerFactory
	providerTypes      map[config.ProviderType]secretProviderFactory
	authenticatorTypes map[config.AuthenticatorType]authenticatorFactory
	accounterTypes     map[config.AccounterType]accounterFactory
	handlerTypes       map[config.HandlerType]handlerFactory
	query              chan queryGet
	warm               chan struct{}
}

// BlockUntilLoaded will block until we are warmed up with parsed config
func (l Loader) BlockUntilLoaded() {
	<-l.warm
}

// Get implements tq.SecretProvider.  The underlying user types and associated configs
// are protected by this method.
func (l Loader) Get(ctx context.Context, remote net.Addr) ([]byte, tq.Handler, error) {
	q := queryGet{ctx: ctx, remote: remote, cb: make(chan secretProvider)}
	l.query <- q
	secretProviderGet.Inc()
	sp := <-q.cb
	secretProviderGet.Dec()
	return sp.secret, sp.handler, sp.err
}

// get is a protected method that searches for a matching provider.  we first check the
// remote connection should even be allowed.
func (l Loader) get(ctx context.Context, providers []tq.SecretProvider, remote net.Addr) ([]byte, tq.Handler, error) {
	for _, sp := range providers {
		secret, handler, err := sp.Get(ctx, remote)
		if err != nil || secret == nil || handler == nil {
			l.Debugf(ctx, "remote [%v], %v", remote, err)
			continue
		}
		secretKnown.Inc()
		return secret, handler, err
	}
	secretUnknown.Inc()
	return nil, nil, fmt.Errorf("remote [%v] has no secret providers", remote)
}

// updates is the protected update/query loop for Loader
func (l *Loader) updates() {
	var warm sync.Once
	// providers lives here so as to remain protected from data race conditions on update/get
	providers := []tq.SecretProvider{}
	// prefix filters are here for the same reason, race condition protection
	prefixDeny, prefixAllow := newPrefixFilter(nil), newPrefixFilter(nil)
	for {
		select {
		case c := <-l.Config():
			providers = l.build(c)
			l.Infof(l.ctx, "updated all providers from config source")
			prefixDeny, prefixAllow = l.createPrefixFilters(c)
			l.Infof(l.ctx, "updated all prefix filters, where available, from config source")
			buildUpdate.Inc()
			// notify that we are warmed, but one time only
			warm.Do(func() { close(l.warm) })
		case q := <-l.query:
			// prefixFilter will log to prom counters and also act as a quick fail for prefixes that do not pass
			// muster.  this pevents unnecessary load on scanning SecretProviders
			if prefixDeny.deny(q.remote) {
				q.cb <- secretProvider{err: fmt.Errorf("remote address connection not allowed by prefixDeny filter [%v]", q.remote.String())}
				close(q.cb)
				break
			}
			if !prefixAllow.allow(q.remote) {
				q.cb <- secretProvider{err: fmt.Errorf("remote address connection not allowed by prefixAllow filter [%v]", q.remote.String())}
				close(q.cb)
				break
			}
			secret, handler, err := l.get(q.ctx, providers, q.remote)
			q.cb <- secretProvider{secret: secret, handler: handler, err: err}
			close(q.cb)
			buildGet.Inc()
		}
	}
}

// createPrefixFilters inits new filters based on config
func (l *Loader) createPrefixFilters(c config.ServerConfig) (*prefixFilter, *prefixFilter) {
	prefixDeny := newPrefixFilter(strToIPNet(c.PrefixDeny))
	prefixAllow := newPrefixFilter(strToIPNet(c.PrefixAllow))
	l.Infof(l.ctx, "loaded [%v] deny filters and [%v] allow filters", len(c.PrefixDeny), len(c.PrefixAllow))
	return prefixDeny, prefixAllow
}

// strToIPNet generate a set of prefixes for the server to check
// net.Conn.RemAddr addresses against.  Any non-confomring client connections
// will be dropped
func strToIPNet(prefixes []string) []*net.IPNet {
	allowed := make([]*net.IPNet, 0, len(prefixes))
	for _, cidr := range prefixes {
		if _, ipNet, _ := net.ParseCIDR(cidr); ipNet != nil {
			allowed = append(allowed, ipNet)
		}
	}
	return allowed
}

type secretProvider struct {
	secret  []byte
	handler tq.Handler
	err     error
}

type queryGet struct {
	ctx    context.Context
	remote net.Addr
	cb     chan secretProvider
}

// build is admittedly complex.  This is a design tradeoff for allowing a lot of dependency injection options that
// also span an undefined number of config format representations.  Build glues all of these injected types together
// into an internal representation that the server can use.  Build is best effort under all circumstances.  Injected
// dependencies that are misconfigured or incomplete, or config itself that is the same, can result in a server running
// without any config.  In that case, all client calls to the service will fail closed.
func (l Loader) build(c config.ServerConfig) []tq.SecretProvider {
	providers := make([]tq.SecretProvider, 0, len(c.Secrets))
	for _, provider := range c.Secrets {
		// TODO add stringer to provider.Type
		l.Infof(l.ctx, "processing secret config [%v:%v]", provider.Name, provider.Type)
		// extract scoped user map
		users := map[string]*config.AAA{}
		for _, u := range c.Users {
			// does this user belong to this scope?
			if !u.HasScope(provider.Name) {
				// nope, skip
				continue
			}
			scope.Inc()

			// localize the user to this scope
			u.LocalizeToScope(provider.Name)

			if _, exists := users[u.Name]; exists {
				// we do we do this? it allows for users overrides to be applied on top
				// of previous entries.
				l.Errorf(l.ctx, "duplicate username detected, overwriting previous entry; scope [%v] user [%v]", provider.Name, u.Name)
				userScopeDuplicate.Inc()
			}
			l.reduceAuthenticatorAccounterFromGroups(provider.Name, &u)

			// general flow here is that we opportunistically build the three As of AAA.  If we hit an error
			// we try to keep going, providing a default implementation which fails closed.  Since all three
			// As are not required by the rfc.

			opts := []config.AAAOption{}
			if a, err := l.authorizerProvider.New(u); err == nil {
				opts = append(opts, config.SetAAAAuthorizer(a))
			} else {
				userAuthorizerUnassigned.Inc()
				l.Infof(l.ctx, "no authorizer available in scope [%v] for user [%v]", provider.Name, u.Name)
			}

			if u.Authenticator != nil {
				// this needs to be smarter for options retrieval
				af := l.authenticatorTypes[u.Authenticator.Type]
				if af != nil {
					a, err := af.New(u.Name, u.Authenticator.Options)
					if err != nil {
						userAuthenticatorBadConfigRef.Inc()
						l.Errorf(l.ctx, "authenticator factory error in scope [%v], user [%v] will not be added; %v", provider.Name, u.Name, err)
						continue
					}
					opts = append(opts, config.SetAAAAuthenticator(a))
				} else {
					userAuthenticatorUnassigned.Inc()
					l.Infof(l.ctx, "no authenticator assigned to authenticator type [%v] in scope [%v] on user [%v]", u.Authenticator.Type, provider.Name, u.Name)
				}
			}
			if u.Accounter != nil {
				acf := l.accounterTypes[u.Accounter.Type]
				if acf != nil {
					opts = append(opts, config.SetAAAAccounter(acf.New(u.Accounter.Options)))
				} else {
					userAccounterUnassigned.Inc()
					l.Errorf(l.ctx, "no accounter assigned to accounter type [%v] in scope [%v] on user [%v]", u.Accounter.Type, provider.Name, u.Name)
				}
			}
			l.Debugf(l.ctx, "loaded user [%v] into scope [%v]", u.Name, provider.Name)
			users[u.Name] = config.NewAAA(opts...)
			userTotal.Inc()
		}
		if len(users) == 0 {
			l.Errorf(l.ctx, "no users associated to scope [%v]; skipping scope", provider.Name)
			userScopeUnassigned.Inc()
			l.Errorf(l.ctx, "no users associated to secret config scope [%v]", provider.Name)
			continue
		}
		handlerType := l.handlerTypes[provider.Handler.Type]
		if handlerType == nil {
			l.Errorf(l.ctx, "no handler assigned to provider type [%v] in scope [%v]. Skipping scope...", provider.Type, provider.Name)
			continue
		}
		userConfig := l.configProvider.New(users)
		handler := handlerType.New(l.ctx, userConfig, provider.Handler.Options)
		providerType := l.providerTypes[provider.Type]
		if providerType == nil {
			l.Errorf(l.ctx, "no provider assigned to provider type [%v] in scope [%v]; [%v] users not added", provider.Type, provider.Name, len(users))
			secretProviderMissing.Inc()
			continue
		}
		secretFunc := l.keychainProvider.Add(provider.Secret)
		p := providerType.New(l.ctx, provider, handler, secretFunc)
		if p == nil {
			l.Errorf(l.ctx, "provider factory is nil in scope [%v]; no users will be added", provider.Name)
			providerFactoryMissing.Inc()
			continue
		}
		providers = append(providers, p)
	}
	return providers
}

// reduceAuthenticatorAccounterFromGroups applies authenticators and accounters from groups down to the user level.
// the first occurence of either will be used exclusively over any others that subsequent groups may contain.
// When both an authenticator and accounter have been set on the user, this loop exits.
func (l Loader) reduceAuthenticatorAccounterFromGroups(scope string, u *config.User) {
	if u.Authenticator != nil {
		userOverrideAuthenticator.Inc()

	}
	if u.Accounter != nil {
		userOverrideAccounter.Inc()
	}
	if u.Authenticator != nil && u.Accounter != nil {
		l.Infof(l.ctx, "skipping authenticator and accounter for scope [%v] user [%v], both are already set at the user level", scope, u.Name)
		return
	}
	for _, g := range u.Groups {
		if g.Authenticator != nil {
			if u.Authenticator != nil {
				l.Infof(l.ctx, "skipping authenticator for scope [%v] user [%v], it's already set at the user level", scope, u.Name)
			} else {
				u.Authenticator = g.Authenticator
			}
		}
		if g.Accounter != nil {
			if u.Accounter != nil {
				l.Infof(l.ctx, "skipping accounter for scope [%v] user [%v], it's already set at the user level", scope, u.Name)
			} else {
				u.Accounter = g.Accounter
			}
		}
		if u.Authenticator != nil && u.Accounter != nil {
			return
		}
	}
}
