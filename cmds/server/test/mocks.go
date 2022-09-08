/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"context"
	"fmt"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"

	"github.com/facebookincubator/tacquito/cmds/server/config/accounters/local"
	"github.com/facebookincubator/tacquito/cmds/server/config/authenticators/bcrypt"
	"github.com/facebookincubator/tacquito/cmds/server/config/authorizers/stringy"
	"github.com/facebookincubator/tacquito/cmds/server/config/secret"
	"github.com/facebookincubator/tacquito/cmds/server/config/secret/prefix"
	"github.com/facebookincubator/tacquito/cmds/server/handlers"
	"github.com/facebookincubator/tacquito/cmds/server/loader"
	"github.com/facebookincubator/tacquito/cmds/server/loader/yaml"
)

// Test ...
type Test struct {
	Name   string
	Secret []byte
	Seq    []Sequence
}

// Sequence ...
type Sequence struct {
	Packet         *tq.Packet
	ValidateHeader func(header *tq.Header) error
	ValidateBody   func(response []byte) error
	Validate       func(p *tq.Packet) error
}

// MockSecretProvider creates a mock secret provider
func MockSecretProvider(ctx context.Context, logger loggerProvider, configPath string) (tq.SecretProvider, error) {
	accountingLogger, err := local.New(logger, local.SetLogSinkDefault("/tmp/tacquito_accounting.log", "tacquito"))
	if err != nil {
		return nil, fmt.Errorf("error building accounting logger; %v", err)
	}
	sp, err := loader.NewLocalConfig(
		ctx,
		configPath,
		yaml.New(),
		loader.SetLoggerProvider(logger),
		loader.SetKeychainProvider(secret.New()),
		loader.SetConfigProvider(config.New()),
		loader.SetAuthorizerProvider(stringy.New(logger)),
		loader.RegisterSecretProviderType(config.PREFIX, prefix.New(logger)),
		loader.RegisterAuthenticator(config.BCRYPT, bcrypt.New(logger, &shh{})),
		loader.RegisterAccounter(config.FILE, accountingLogger),
		loader.RegisterHandlerType(config.START, handlers.NewStart(logger)),
	)
	if err != nil {
		return nil, err
	}
	sp.BlockUntilLoaded()
	return sp, nil
}

type shh struct{}

// GetSecret ...
func (s *shh) GetSecret(ctx context.Context, name, group string) ([]byte, error) {
	fmt.Println(name, group)
	return []byte("cisco"), nil
}
