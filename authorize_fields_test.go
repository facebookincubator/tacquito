/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"testing"
)

func TestArgsStripCR(t *testing.T) {
	args := Args{
		"cmd=show",
		"cmd-arg=version",
		"cmd-arg=<cr>",
	}
	expected := "version"
	if v := args.CommandArgsNoLE(); v != expected {
		t.Fatalf("failed to get command args, expected %s, got %s", expected, v)
	}
}

func TestArgsStripCRInMiddle(t *testing.T) {
	args := Args{
		"cmd=show",
		"cmd-arg=version",
		"cmd-arg=<cr>",
		"cmd-arg=actual",
		"cmd-arg=line",
		"cmd-arg=ending",
		"cmd-arg=<cr>",
	}
	expected := "version <cr> actual line ending"
	if v := args.CommandArgsNoLE(); v != expected {
		t.Fatalf("failed to get command args, expected %s, got %s", expected, v)
	}
}
