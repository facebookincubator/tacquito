/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package stringy

import (
	"context"
	"math/rand"
	"testing"
	"time"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"

	"github.com/stretchr/testify/assert"
)

func TestFilters(t *testing.T) {
	values := []string{"foo=bar", "k=", "baz*bar", "cmd*"}
	f := tq.Args{}
	f.Append(values...)
	assert.Equal(t, values, f.Args())

	// shuffle it a bunch of times and make sure values
	// are still legit
	for i := 0; i <= 10; i++ {
		rand.Shuffle(len(values), func(i, j int) { values[i], values[j] = values[j], values[i] })
		f := tq.Args{}
		f.Append(values...)
		assert.Equal(t, values, f.Args())
	}
}

type specialMatchTest struct {
	name   string
	setup  func() (*tq.AuthorRequest, config.User)
	expect func(*testing.T, string, []string, tq.AuthorStatus)
}

// shuffle is used to shuffle the args in tests
func shuffle(args tq.Args) {
	rand.Seed(time.Now().UnixNano())
	rand.Shuffle(len(args), func(i, j int) { args[i], args[j] = args[j], args[i] })
}

func TestSpecialMatchers(t *testing.T) {
	tests := []specialMatchTest{
		{
			name: "basic match",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						// scope is injected here artifically.  it's done in the stringy handler in production
						tq.Args{"service=shell", "priv-lvl*15", "shell:roles*admin", "scope=foo-scope"},
					),
				)
				// shuffle in place
				shuffle(r.Args)
				u := config.User{
					Scopes: []string{"foo-scope", "bar-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"15"}, Optional: true},
								{Name: "shell:roles", Values: []string{"admin"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"foo-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"bar-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
					},
				}
				// loader will do the localization, but we don't have loader here, so mimic
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*15", "shell:roles*admin", "firepower*or bust"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status)
			},
		},
		{
			name: "match that has two values",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						// scope is injected here artifically.  it's done in the stringy handler in production
						tq.Args{"service=shell", "priv-lvl*15", "shell:roles*admin", "scope=foo-scope"},
					),
				)
				// shuffle in place
				shuffle(r.Args)
				u := config.User{
					Scopes: []string{"foo-scope", "bar-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"15"}, Optional: true},
								{Name: "shell:roles", Values: []string{"admin"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "priv-lvl", Values: []string{"15"}},
								{Name: "scope", Values: []string{"foo-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"bar-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
					},
				}
				// loader will do the localization, but we don't have loader here, so mimic
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*15", "shell:roles*admin", "firepower*or bust"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status, "%s failed", name)
			},
		},
		{
			name: "no match that has two values",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						// scope is injected here artifically.  it's done in the stringy handler in production
						tq.Args{"service=shell", "priv-lvl*15", "shell:roles*admin", "scope=foo-scope"},
					),
				)
				// shuffle in place
				shuffle(r.Args)
				u := config.User{
					Scopes: []string{"foo-scope", "bar-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"15"}, Optional: true},
								{Name: "shell:roles", Values: []string{"admin"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "priv-lvl", Values: []string{"1"}}, // should force a no match
								{Name: "scope", Values: []string{"foo-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"bar-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
					},
				}
				// loader will do the localization, but we don't have loader here, so mimic
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*15", "shell:roles*admin"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status, "%s failed", name)
			},
		},
		{
			name: "basic match with no values",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						// scope is injected here artifically.  it's done in the stringy handler in production
						tq.Args{"service=shell", "priv-lvl*", "shell:roles*", "scope=foo-scope"},
					),
				)
				// shuffle in place
				shuffle(r.Args)
				u := config.User{
					Scopes: []string{"foo-scope", "bar-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"15"}, Optional: true},
								{Name: "shell:roles", Values: []string{"admin"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"foo-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"bar-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
					},
				}
				// loader will do the localization, but we don't have loader here, so mimic
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*15", "shell:roles*admin", "firepower*or bust"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status, "%s failed", name)
			},
		},
		{
			name: "basic match with no values using = and *",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						// scope is injected here artifically.  it's done in the stringy handler in production
						tq.Args{"service=shell", "cmd=", "cisco-av-pair*", "shell:roles*", "scope=foo-scope"},
					),
				)
				// shuffle in place
				shuffle(r.Args)
				u := config.User{
					Scopes: []string{"foo-scope", "bar-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"15"}, Optional: true},
								{Name: "shell:roles", Values: []string{"admin"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"foo-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"bar-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
					},
				}
				// loader will do the localization, but we don't have loader here, so mimic
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*15", "shell:roles*admin", "firepower*or bust"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status, "%s failed", name)
			},
		},
		{
			name: "no match with no values using = and *",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						// scope is injected here artifically.  it's done in the stringy handler in production
						tq.Args{"service=shell", "cmd=", "cisco-av-pair*", "shell:roles*", "scope=foo-scope"},
					),
				)
				// shuffle in place
				shuffle(r.Args)
				u := config.User{
					Scopes: []string{"foo-scope", "bar-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"15"}, Optional: true},
								{Name: "shell:roles", Values: []string{"admin"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"foo-scope"}},
								{Name: "cisco-av-pair", Values: []string{"fruit"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"bar-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
					},
				}
				// loader will do the localization, but we don't have loader here, so mimic
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*15", "shell:roles*admin"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status, "%s failed", name)
			},
		},
		{
			name: "match with no values using = and * to demonstrate we can match on the attribute only",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						// scope is injected here artifically.  it's done in the stringy handler in production
						tq.Args{"service=shell", "cmd=", "cisco-av-pair*", "shell:roles*", "scope=foo-scope"},
					),
				)
				// shuffle in place
				shuffle(r.Args)
				u := config.User{
					Scopes: []string{"foo-scope", "bar-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"15"}, Optional: true},
								{Name: "shell:roles", Values: []string{"admin"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"foo-scope"}},
								{Name: "cisco-av-pair"},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"bar-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
					},
				}
				// loader will do the localization, but we don't have loader here, so mimic
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*15", "shell:roles*admin", "firepower*or bust"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status, "%s failed", name)
			},
		},
		{
			name: "match with no values using = and * to demonstrate we don't match on a non-matching attribute",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						// scope is injected here artifically.  it's done in the stringy handler in production
						tq.Args{"service=shell", "cmd=", "cisco-av-pair*", "shell:roles*", "scope=foo-scope"},
					),
				)
				// shuffle in place
				shuffle(r.Args)
				u := config.User{
					Scopes: []string{"foo-scope", "bar-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"15"}, Optional: true},
								{Name: "shell:roles", Values: []string{"admin"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"foo-scope"}},
								{Name: "cisco-av-pair-fake"},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "scope", Values: []string{"bar-scope"}},
							},
							SetValues: []config.Value{
								{Name: "firepower", Values: []string{"or bust"}, Optional: true},
							},
						},
					},
				}
				// loader will do the localization, but we don't have loader here, so mimic
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*15", "shell:roles*admin"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status, "%s failed", name)
			},
		},
	}
	for _, test := range tests {
		r, u := test.setup()
		sa := NewSessionBasedAuthorizer(context.Background(), NewDefaultLogger(), *r, u)
		resp, status := sa.evaluate()
		test.expect(t, test.name, resp, status)
	}
}

func TestRemAddrMatchers(t *testing.T) {
	tests := []specialMatchTest{
		{
			name: "ipv6 /128 match returns rem-addr service priv-lvl plus fallback",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						tq.Args{"service=shell", "cmd=", "scope=foo-scope"},
					),
					tq.SetAuthorRequestRemAddr(tq.AuthenRemAddr("2620:10d:c0a8:b3::31")),
				)
				u := config.User{
					Scopes: []string{"foo-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "rem-addr", Values: []string{"2620:10d:c0a8:b3::31/128"}},
							},
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"1"}, Optional: true},
							},
						},
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"14"}, Optional: true},
							},
						},
					},
				}
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*1", "priv-lvl*14"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status, "%s failed", name)
			},
		},
		{
			name: "ipv6 no match falls through to fallback service",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						tq.Args{"service=shell", "cmd=", "scope=foo-scope"},
					),
					tq.SetAuthorRequestRemAddr(tq.AuthenRemAddr("2620:10d:c0a8:b3::32")),
				)
				u := config.User{
					Scopes: []string{"foo-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "rem-addr", Values: []string{"2620:10d:c0a8:b3::31/128"}},
							},
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"1"}, Optional: true},
							},
						},
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"14"}, Optional: true},
							},
						},
					},
				}
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*14"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status, "%s failed", name)
			},
		},
		{
			name: "supernet match returns both matched and fallback priv-lvl",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						tq.Args{"service=shell", "cmd=", "scope=foo-scope"},
					),
					tq.SetAuthorRequestRemAddr(tq.AuthenRemAddr("2620:10d:c0a8:b3::32")),
				)
				u := config.User{
					Scopes: []string{"foo-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "rem-addr", Values: []string{"2620:10d:c0a8:b3::/64"}},
							},
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"3"}, Optional: true},
							},
						},
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"14"}, Optional: true},
							},
						},
					},
				}
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*3", "priv-lvl*14"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status, "%s failed", name)
			},
		},
		{
			name: "multiple addresses to match on succeeds",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						tq.Args{"service=shell", "cmd=", "scope=foo-scope"},
					),
					tq.SetAuthorRequestRemAddr(tq.AuthenRemAddr("2620:10d:c0a8:b3::32")),
				)
				u := config.User{
					Scopes: []string{"foo-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "rem-addr", Values: []string{"2620:1cbd::/64", "2620:10d:c0a8:b3::/64"}},
							},
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"5"}, Optional: true},
							},
						},
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"14"}, Optional: true},
							},
						},
					},
				}
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*5", "priv-lvl*14"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status, "%s failed", name)
			},
		},
		{
			name: "no rem addr means rem-addr does not match",
			setup: func() (*tq.AuthorRequest, config.User) {
				r := tq.NewAuthorRequest(
					tq.SetAuthorRequestArgs(
						tq.Args{"service=shell", "cmd=", "scope=foo-scope"},
					),
				)
				u := config.User{
					Scopes: []string{"foo-scope"},
					Services: []config.Service{
						{
							Name: "shell",
							Match: []config.Value{
								{Name: "rem-addr", Values: []string{"2620:10d:c0a8:b3::31/128"}},
							},
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"1"}, Optional: true},
							},
						},
						{
							Name: "shell",
							SetValues: []config.Value{
								{Name: "priv-lvl", Values: []string{"14"}, Optional: true},
							},
						},
					},
				}
				u.LocalizeToScope("foo-scope")
				return r, u
			},
			expect: func(t *testing.T, name string, resp []string, status tq.AuthorStatus) {
				assert.Equal(t, []string{"priv-lvl*14"}, resp, "%s failed", name)
				assert.Equal(t, tq.AuthorStatusPassRepl, status, "%s failed", name)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			r, u := test.setup()
			ctx := context.Background()
			sa := NewSessionBasedAuthorizer(ctx, NewDefaultLogger(), *r, u)
			resp, status := sa.evaluate()
			test.expect(t, test.name, resp, status)
		})
	}
}
