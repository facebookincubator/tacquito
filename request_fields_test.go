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
	var f AcctRequestFlag
	f.Set(AcctFlagStart)
	acctRequest := NewAcctRequest(
		SetAcctRequestFlag(f),
		SetAcctRequestMethod(AuthenMethodTacacsPlus),
		SetAcctRequestPrivLvl(PrivLvlRoot),
		SetAcctRequestType(AuthenTypeASCII),
		SetAcctRequestService(AuthenServiceLogin),
		SetAcctRequestPort("4"),
		SetAcctRequestRemAddr("async"),
		SetAcctRequestArgs(Args{Arg("show"), Arg("system")}),
	)
	emptyAcctBody, err := acctRequest.MarshalBinary()
	if err != nil {
		t.Error("failed to marshal an empty AccountRequest, uh oh")
	}

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
			request: Request{Header: *NewHeader(SetHeaderType(Accounting)), Body: emptyAcctBody, Context: withValues(context.Background(), map[ContextKey]string{ContextSessionID: "123", ContextReqID:"1", ContextConnRemoteAddr:"9.9.9.9"})},
			expected: map[string]string{string(ContextSessionID): "123", string(ContextReqID):"1", string(ContextConnRemoteAddr):"9.9.9.9"},
			ctxKeys: []ContextKey{ContextSessionID, ContextReqID, ContextConnRemoteAddr},
		},
	}

	for _, test := range tests {
		fields := test.request.Fields(test.ctxKeys...)
		for expectedKey, expectedValue := range test.expected {
			v, ok := fields[expectedKey]
			if !ok || v != expectedValue {
				t.Fatalf("request fields dont match, got %v, wanted %v", fields, test.expected)
			}
		}
	}
}