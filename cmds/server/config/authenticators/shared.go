/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package authenticators provides reusable functions for types interested in implementing
// custom authenticators
package authenticators

import (
	"fmt"

	tq "github.com/facebookincubator/tacquito"
)

// Methods is a stateless, bag of functionality, meant to be composed into
// specific authenticator types to reduce boilerplate
type Methods struct{}

// GetFields is used in structured logging
func (m Methods) GetFields(request tq.Request) map[string]string {
	if body := m.getAuthenStart(request); body != nil {
		return body.Fields()
	}
	if body := m.getAuthenContinue(request); body != nil {
		return body.Fields()
	}
	return nil
}

// getAuthenStart unmarshalls an authenstart packet
func (m Methods) getAuthenStart(request tq.Request) *tq.AuthenStart {
	var body tq.AuthenStart
	if err := tq.Unmarshal(request.Body, &body); err != nil {
		return nil
	}
	return &body
}

// getAuthenContinue unmarshalls an authencontinue packet
func (m Methods) getAuthenContinue(request tq.Request) *tq.AuthenContinue {
	var body tq.AuthenContinue
	if err := tq.Unmarshal(request.Body, &body); err != nil {
		return nil
	}
	return &body
}

// GetPassword will get the password from an authenstart or authencontinue packet
func (m Methods) GetPassword(request tq.Request) (string, error) {
	if body := m.getAuthenStart(request); body != nil {
		return string(body.Data), nil
	}
	if body := m.getAuthenContinue(request); body != nil {
		return string(body.UserMessage), nil
	}
	return "", fmt.Errorf("missing password")
}
