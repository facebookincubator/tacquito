/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"context"
	"testing"
)

func TestRequestFields(t *testing.T) {
	// we need a request body that will successfully unmarshal
	acctRequest := NewAcctRequest(
		SetAcctRequestMethod(AuthenMethodTacacsPlus),
		SetAcctRequestPrivLvl(PrivLvlRoot),
		SetAcctRequestType(AuthenTypeASCII),
		SetAcctRequestService(AuthenServiceLogin),
		SetAcctRequestPort("4"),
		SetAcctRequestRemAddr("async"),
	)
	acctBody, err := acctRequest.MarshalBinary()
	if err != nil {
		t.Error("failed to marshal an AccountRequest, uh oh")
	}

	// helper to add multiple values to a context
	withValues := func (ctx context.Context, kv map[ContextKey]string) context.Context {
		for k,v := range kv {
			ctx = context.WithValue(ctx, k, v)
		}
		return ctx
	}
	

	tests := []struct {
		name     string
		request  Request
		expected map[string]string
		ctxKeys []ContextKey
	}{
		{
			name: "ensure ContextKeys are added to fields map",
			request: Request{Header: *NewHeader(SetHeaderType(Accounting)), Body: acctBody, Context: withValues(context.Background(), map[ContextKey]string{ContextSessionID: "123", ContextReqID:"1", ContextConnRemoteAddr:"9.9.9.9"})},
			expected: map[string]string{string(ContextSessionID): "123", string(ContextReqID):"1", string(ContextConnRemoteAddr):"9.9.9.9"},
			ctxKeys: []ContextKey{ContextSessionID, ContextReqID, ContextConnRemoteAddr},
		},
	}

	for _, test := range tests {
		fields := test.request.Fields(test.ctxKeys...)
		for expectedKey, expectedValue := range test.expected {
			if v, ok := fields[expectedKey]; !ok || v != expectedValue {
				t.Fatalf("request fields dont match, got %v, wanted %v", fields, test.expected)
			}
		}
	}
}