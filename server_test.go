/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"testing"
)

func TestStrip(t *testing.T) {
	type test struct {
		input string
		want  string
	}

	tests := []test{
		{input: "1.1.1.1", want: "1.1.1.1"},
		{input: "1.1.1.1:23", want: "1.1.1.1"},
		{input: "2001:db8:0:1:1:1:1:1", want: "2001:db8:0:1:1:1:1:1"},
		{input: "2001:db8:0:1:1::1", want: "2001:db8:0:1:1::1"},
		{input: "[2001:db8:0:1:1:1:1:1]:23", want: "2001:db8:0:1:1:1:1:1"},
	}

	for _, tc := range tests {
		got := strip(tc.input)
		if got != tc.want {
			t.Fatalf("unexpected output from strip function: want: %v, got: %v", tc.want, got)
		}
	}
}
