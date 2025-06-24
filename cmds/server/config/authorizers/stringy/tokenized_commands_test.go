/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package stringy

import (
	"testing"

	tq "github.com/facebookincubator/tacquito"

	"github.com/stretchr/testify/assert"
)

func TestSplit(t *testing.T) {
	tests := []struct {
		name      string
		args      tq.Args
		delimiter string
		want      []tq.Args
	}{
		{
			name: "simple command with no delimiter",
			args: tq.Args{
				tq.Arg("service=shell"),
				tq.Arg("cmd=show"),
				tq.Arg("cmd-arg=version"),
				tq.Arg("cmd-arg=<cr>"),
			},
			delimiter: "|",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=show"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
		{
			name: "command with one pipe delimiter",
			args: tq.Args{
				tq.Arg("service=shell"),
				tq.Arg("cmd=show"),
				tq.Arg("cmd-arg=version"),
				tq.Arg("cmd-arg=|"),
				tq.Arg("cmd-arg=grep"),
				tq.Arg("cmd-arg=version"),
				tq.Arg("cmd-arg=<cr>"),
			},
			delimiter: "|",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=show"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=|"),
					tq.Arg("cmd-arg=grep"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
		{
			name: "command with multiple pipe delimiters",
			args: tq.Args{
				tq.Arg("service=shell"),
				tq.Arg("cmd=show"),
				tq.Arg("cmd-arg=version"),
				tq.Arg("cmd-arg=|"),
				tq.Arg("cmd-arg=grep"),
				tq.Arg("cmd-arg=version"),
				tq.Arg("cmd-arg=|"),
				tq.Arg("cmd-arg=wc"),
				tq.Arg("cmd-arg=-l"),
				tq.Arg("cmd-arg=<cr>"),
			},
			delimiter: "|",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=show"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=|"),
					tq.Arg("cmd-arg=grep"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=|"),
					tq.Arg("cmd-arg=wc"),
					tq.Arg("cmd-arg=-l"),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
		{
			name: "command with pipe delimiter and command arguments",
			args: tq.Args{
				tq.Arg("service=shell"),
				tq.Arg("cmd=show"),
				tq.Arg("cmd-arg=version"),
				tq.Arg("cmd-arg=|"),
				tq.Arg("cmd-arg=sudo"),
				tq.Arg("cmd-arg=curl"),
				tq.Arg("cmd-arg=-s"),
				tq.Arg("cmd-arg=-k"),
				tq.Arg("cmd-arg=-X"),
				tq.Arg("cmd-arg=GET"),
				tq.Arg("cmd-arg=https://localhost:8443/api/v1/health"),
				tq.Arg("cmd-arg=|"),
				tq.Arg("cmd-arg=grep"),
				tq.Arg("cmd-arg=-q"),
				tq.Arg("cmd-arg=\"UP\""),
				tq.Arg("cmd-arg=<cr>"),
			},
			delimiter: "|",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=show"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=|"),
					tq.Arg("cmd-arg=sudo"),
					tq.Arg("cmd-arg=curl"),
					tq.Arg("cmd-arg=-s"),
					tq.Arg("cmd-arg=-k"),
					tq.Arg("cmd-arg=-X"),
					tq.Arg("cmd-arg=GET"),
					tq.Arg("cmd-arg=https://localhost:8443/api/v1/health"),
					tq.Arg("cmd-arg=<cr>"),
				},
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=|"),
					tq.Arg("cmd-arg=grep"),
					tq.Arg("cmd-arg=-q"),
					tq.Arg("cmd-arg=\"UP\""),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
		{
			name: "command with pipe character in quotes",
			args: tq.Args{
				tq.Arg("service=shell"),
				tq.Arg("cmd=echo"),
				tq.Arg("cmd-arg=\"This | has a pipe\""),
				tq.Arg("cmd-arg=<cr>"),
			},
			delimiter: "|",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=echo"),
					tq.Arg("cmd-arg=\"This | has a pipe\""),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
		{
			name: "command with pipe character in single quotes",
			args: tq.Args{
				tq.Arg("service=shell"),
				tq.Arg("cmd=echo"),
				tq.Arg("cmd-arg='This | has a pipe'"),
				tq.Arg("cmd-arg=<cr>"),
			},
			delimiter: "|",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=echo"),
					tq.Arg("cmd-arg='This | has a pipe'"),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
		{
			name: "command with additional pipe character at the end",
			args: tq.Args{
				tq.Arg("service=shell"),
				tq.Arg("cmd=show"),
				tq.Arg("cmd-arg=version"),
				tq.Arg("cmd-arg=|"),
				tq.Arg("cmd-arg=grep"),
				tq.Arg("cmd-arg=version"),
				tq.Arg("cmd-arg=|"),
				tq.Arg("cmd-arg=<cr>"),
			},
			delimiter: "|",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=show"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=|"),
					tq.Arg("cmd-arg=grep"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=|"),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
		{
			name: "command with escaped pipe character",
			args: tq.Args{
				tq.Arg("service=shell"),
				tq.Arg("cmd=echo"),
				tq.Arg("cmd-arg=This"),
				tq.Arg("cmd-arg=\\|"),
				tq.Arg("cmd-arg=has"),
				tq.Arg("cmd-arg=a"),
				tq.Arg("cmd-arg=pipe"),
				tq.Arg("cmd-arg=<cr>"),
			},
			delimiter: "|",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=echo"),
					tq.Arg("cmd-arg=This"),
					tq.Arg("cmd-arg=\\|"),
					tq.Arg("cmd-arg=has"),
					tq.Arg("cmd-arg=a"),
					tq.Arg("cmd-arg=pipe"),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
		{
			name:      "empty command",
			args:      tq.Args{},
			delimiter: "|",
			want:      []tq.Args{{}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.Split(tt.delimiter)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestSplitWithDifferentDelimiters(t *testing.T) {
	args := tq.Args{
		tq.Arg("service=shell"),
		tq.Arg("cmd=show"),
		tq.Arg("cmd-arg=version"),
		tq.Arg("cmd-arg=;"),
		tq.Arg("cmd-arg=grep"),
		tq.Arg("cmd-arg=version"),
		tq.Arg("cmd-arg=&&"),
		tq.Arg("cmd-arg=wc"),
		tq.Arg("cmd-arg=-l"),
		tq.Arg("cmd-arg=<cr>"),
	}

	tests := []struct {
		name      string
		delimiter string
		want      []tq.Args
	}{
		{
			name:      "semicolon delimiter",
			delimiter: ";",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=show"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=;"),
					tq.Arg("cmd-arg=grep"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=&&"),
					tq.Arg("cmd-arg=wc"),
					tq.Arg("cmd-arg=-l"),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
		{
			name:      "ampersand delimiter",
			delimiter: "&&",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=show"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=;"),
					tq.Arg("cmd-arg=grep"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=&&"),
					tq.Arg("cmd-arg=wc"),
					tq.Arg("cmd-arg=-l"),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := args.Split(tt.delimiter)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestMaxSplitCount tests that MaxSplitCount correctly limits the number of delimiters
func TestMaxSplitCount(t *testing.T) {
	// Create a request with MaxSplitCount+1 delimiters (6 pipes)
	tooManyPipes := tq.Args{
		tq.Arg("service=shell"),
		tq.Arg("cmd=show"),
		tq.Arg("cmd-arg=version"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=grep"),
		tq.Arg("cmd-arg=something"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=awk"),
		tq.Arg("cmd-arg={print $1}"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=sort"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=uniq"),
		tq.Arg("cmd-arg=|"), // MaxSplitCount
		tq.Arg("cmd-arg=wc"),
		tq.Arg("cmd-arg=-l"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=cat"),
		tq.Arg("cmd-arg=<cr>"),
	}

	result := tooManyPipes.Split("|")
	assert.Nil(t, result, "Split should return nil when the number of delimiters exceeds MaxSplitCount")

	// positive test case
	exactPipes := tq.Args{
		tq.Arg("service=shell"),
		tq.Arg("cmd=show"),
		tq.Arg("cmd-arg=version"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=grep"),
		tq.Arg("cmd-arg=something"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=awk"),
		tq.Arg("cmd-arg={print $1}"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=sort"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=uniq"),
		tq.Arg("cmd-arg=|"), // MaxSplitCount
		tq.Arg("cmd-arg=wc"),
		tq.Arg("cmd-arg=-l"),
		tq.Arg("cmd-arg=<cr>"),
	}

	result = exactPipes.Split("|")
	assert.NotNil(t, result, "Split should not return nil when the number of delimiters equals MaxSplitCount")
	assert.Equal(t, 6, len(result), "Split should return MaxSplitCount+1 commands when the number of delimiters equals MaxSplitCount")

	// Verify the first and last commands in the split result
	assert.Equal(t, "show", result[0].Command(), "First command should be 'show'")
	assert.Equal(t, "|", result[5].Command(), "Last command should be '|'")
	assert.Equal(t, "wc -l", result[5].CommandArgsNoLE(), "Last command args should be 'wc -l'")
}

// TestSplitEdgeCases tests edge cases for the Split function
func TestSplitEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		args      tq.Args
		delimiter string
		want      []tq.Args
	}{
		{
			name: "delimiter at the beginning",
			args: tq.Args{
				tq.Arg("service=shell"),
				tq.Arg("cmd=|"),
				tq.Arg("cmd-arg=show"),
				tq.Arg("cmd-arg=version"),
				tq.Arg("cmd-arg=<cr>"),
			},
			delimiter: "|",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=|"),
					tq.Arg("cmd-arg=show"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
		{
			name: "delimiter at the end",
			args: tq.Args{
				tq.Arg("service=shell"),
				tq.Arg("cmd=show"),
				tq.Arg("cmd-arg=version"),
				tq.Arg("cmd-arg=|"),
				tq.Arg("cmd-arg=<cr>"),
			},
			delimiter: "|",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=show"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=|"),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
		{
			name: "consecutive delimiters",
			args: tq.Args{
				tq.Arg("service=shell"),
				tq.Arg("cmd=show"),
				tq.Arg("cmd-arg=version"),
				tq.Arg("cmd-arg=|"),
				tq.Arg("cmd-arg=|"),
				tq.Arg("cmd-arg=grep"),
				tq.Arg("cmd-arg=version"),
				tq.Arg("cmd-arg=<cr>"),
			},
			delimiter: "|",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=show"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=|"),
					tq.Arg("cmd-arg=<cr>"),
				},
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=|"),
					tq.Arg("cmd-arg=grep"),
					tq.Arg("cmd-arg=version"),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
		{
			name: "only delimiter",
			args: tq.Args{
				tq.Arg("service=shell"),
				tq.Arg("cmd=|"),
				tq.Arg("cmd-arg=<cr>"),
			},
			delimiter: "|",
			want: []tq.Args{
				{
					tq.Arg("service=shell"),
					tq.Arg("cmd=|"),
					tq.Arg("cmd-arg=<cr>"),
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.args.Split(tt.delimiter)
			assert.Equal(t, tt.want, got)
		})
	}
}
