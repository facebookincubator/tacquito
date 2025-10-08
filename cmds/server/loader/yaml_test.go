/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package loader

import (
	"testing"

	"github.com/facebookincubator/tacquito/cmds/server/config"
	"github.com/facebookincubator/tacquito/cmds/server/loader/yaml"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

func TestYamlLoad(t *testing.T) {
	l := yaml.New()
	go func() {
		err := l.Load("./testdata/test_config.yaml")
		assert.NoError(t, err)
	}()
	// if you get a bad config parse error, this will block because of how buck hides stderr/out
	actual := <-l.Config()
	spew.Dump(l)

	bcrypt := &config.Authenticator{
		Type:    config.BCRYPT,
		Options: map[string]string{"keychain": "tacquito", "key": "password"},
	}
	stderr := &config.Accounter{
		Name:    "stderr",
		Type:    config.STDERR,
		Options: map[string]string{"foo": "bar"},
	}
	conft := config.Command{Name: "configure", Match: []string{"terminal", "exclusive"}, Action: config.PERMIT}
	confb := config.Command{Name: "configure", Match: []string{"batch"}, Action: config.PERMIT}
	noc := config.Group{
		Name: "noc",
		Services: []config.Service{
			{
				Name: "enable",
				SetValues: []config.Value{
					{Name: "priv-lvl", Values: []string{"15"}},
				},
			},
		},
		Commands:      []config.Command{conft, confb},
		Authenticator: bcrypt,
		Accounter:     stderr,
	}

	users := []config.User{
		{
			Name:   "mr_uses_group",
			Scopes: []string{"localhost"},
			Groups: []config.Group{noc},
		},
		{
			Name:   "mr_no_group",
			Scopes: []string{"localhost"},
			Services: []config.Service{
				{
					Name: "enable",
					SetValues: []config.Value{
						{Name: "priv-lvl", Values: []string{"15"}},
					},
				},
			},
			Commands:      []config.Command{conft},
			Authenticator: bcrypt,
			Accounter:     stderr,
		},
		{
			Name:     "ms_commands_only",
			Scopes:   []string{"localhost"},
			Commands: []config.Command{conft},
		},
	}

	expected := config.ServerConfig{
		Users: users,
		Secrets: []config.SecretConfig{
			{
				Name:    "localhost",
				Secret:  config.Keychain{Group: "tacquito", Key: "fooman"},
				Handler: config.Handler{Type: config.START},
				Type:    config.PREFIX,
				Options: map[string]string{
					"prefixes": "[\n  \"::0/0\"\n]\n",
				},
			},
		},
	}

	assert.Equal(t, expected.Users, actual.Users)
	assert.Equal(t, expected.Secrets, actual.Secrets)
}
