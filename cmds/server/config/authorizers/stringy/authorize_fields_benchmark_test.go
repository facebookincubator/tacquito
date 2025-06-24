/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package stringy

import (
	"testing"

	tq "github.com/facebookincubator/tacquito"
)

// BenchmarkSplitNoDelimiter benchmarks the Split function with a command that has no delimiter
func BenchmarkSplitNoDelimiter(b *testing.B) {
	args := tq.Args{
		tq.Arg("service=shell"),
		tq.Arg("cmd=show"),
		tq.Arg("cmd-arg=version"),
		tq.Arg("cmd-arg=<cr>"),
	}
	delimiter := "|"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = args.Split(delimiter)
	}
}

// BenchmarkSplitOneDelimiter benchmarks the Split function with a command that has one delimiter
func BenchmarkSplitOneDelimiter(b *testing.B) {
	args := tq.Args{
		tq.Arg("service=shell"),
		tq.Arg("cmd=show"),
		tq.Arg("cmd-arg=version"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=grep"),
		tq.Arg("cmd-arg=version"),
		tq.Arg("cmd-arg=<cr>"),
	}
	delimiter := "|"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = args.Split(delimiter)
	}
}

// BenchmarkSplitMultipleDelimiters benchmarks the Split function with a command that has multiple delimiters
func BenchmarkSplitMultipleDelimiters(b *testing.B) {
	args := tq.Args{
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
	}
	delimiter := "|"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = args.Split(delimiter)
	}
}

// BenchmarkSplitDifferentDelimiter benchmarks the Split function with a different delimiter
func BenchmarkSplitDifferentDelimiter(b *testing.B) {
	args := tq.Args{
		tq.Arg("service=shell"),
		tq.Arg("cmd=show"),
		tq.Arg("cmd-arg=version"),
		tq.Arg("cmd-arg=;"),
		tq.Arg("cmd-arg=grep"),
		tq.Arg("cmd-arg=version"),
		tq.Arg("cmd-arg=<cr>"),
	}
	delimiter := ";"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = args.Split(delimiter)
	}
}

// BenchmarkSplitMaxDelimiters benchmarks the Split function with the maximum allowed number of delimiters
func BenchmarkSplitMaxDelimiters(b *testing.B) {
	// Create a request with MaxSplitCount delimiters (5 pipes)
	args := tq.Args{
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
	delimiter := "|"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = args.Split(delimiter)
	}
}

// BenchmarkSplitExceedMaxDelimiters benchmarks the Split function with more than the maximum allowed number of delimiters
func BenchmarkSplitExceedMaxDelimiters(b *testing.B) {
	args := tq.Args{
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
		tq.Arg("cmd-arg=|"), // Exceeds MaxSplitCount
		tq.Arg("cmd-arg=cat"),
		tq.Arg("cmd-arg=<cr>"),
	}
	delimiter := "|"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = args.Split(delimiter)
	}
}

// BenchmarkSplitLongCommand benchmarks the Split function with a long command
func BenchmarkSplitLongCommand(b *testing.B) {
	args := tq.Args{
		tq.Arg("service=shell"),
		tq.Arg("cmd=show"),
		tq.Arg("cmd-arg=interfaces"),
		tq.Arg("cmd-arg=description"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=grep"),
		tq.Arg("cmd-arg=-v"),
		tq.Arg("cmd-arg=down"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=grep"),
		tq.Arg("cmd-arg=-v"),
		tq.Arg("cmd-arg=admin"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=sort"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=column"),
		tq.Arg("cmd-arg=-t"),
		tq.Arg("cmd-arg=<cr>"),
	}
	delimiter := "|"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = args.Split(delimiter)
	}
}

// BenchmarkSplitConsecutiveDelimiters benchmarks the Split function with consecutive delimiters
func BenchmarkSplitConsecutiveDelimiters(b *testing.B) {
	args := tq.Args{
		tq.Arg("service=shell"),
		tq.Arg("cmd=show"),
		tq.Arg("cmd-arg=version"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=|"),
		tq.Arg("cmd-arg=grep"),
		tq.Arg("cmd-arg=version"),
		tq.Arg("cmd-arg=<cr>"),
	}
	delimiter := "|"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = args.Split(delimiter)
	}
}

// BenchmarkSplitEmptytq.Args benchmarks the Split function with empty tq.Args
func BenchmarkSplitEmptyArgs(b *testing.B) {
	args := tq.Args{}
	delimiter := "|"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = args.Split(delimiter)
	}
}
