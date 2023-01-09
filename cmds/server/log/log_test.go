/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package log

import (
	"context"
	"fmt"
	"io"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

// benchTest is used for allocation testing
type benchTest struct {
	name     string
	fn       func(b *testing.B)
	expected func(name string, r testing.BenchmarkResult)
}

// TestLog0 benchmarks allocations for our logger
func TestLog0Allocation(t *testing.T) {
	tests := []benchTest{
		{
			name: "BenchmarkLog0",
			fn:   BenchmarkLog0,
			expected: func(name string, r testing.BenchmarkResult) {
				t.Log(spew.Sdump(r))
				expectedAllocs := 0
				actual := r.AllocsPerOp()
				assert.EqualValues(t, expectedAllocs, actual, fmt.Sprintf("%s allocations were not nominal; wanted %v got %v", name, expectedAllocs, actual))
			},
		},
		{
			name: "BenchmarkLog10",
			fn:   BenchmarkLog10,
			expected: func(name string, r testing.BenchmarkResult) {
				t.Log(spew.Sdump(r))
				expectedAllocs := 3
				actual := r.AllocsPerOp()
				assert.EqualValues(t, expectedAllocs, actual, fmt.Sprintf("%s allocations were not nominal; wanted %v got %v", name, expectedAllocs, actual))
			},
		},
		{
			name: "BenchmarkLog10Variadic",
			fn:   BenchmarkLog10Variadic,
			expected: func(name string, r testing.BenchmarkResult) {
				t.Log(spew.Sdump(r))
				expectedAllocs := 3
				actual := r.AllocsPerOp()
				assert.EqualValues(t, expectedAllocs, actual, fmt.Sprintf("%s allocations were not nominal; wanted %v got %v", name, expectedAllocs, actual))
			},
		},
	}
	for _, test := range tests {
		r := testing.Benchmark(test.fn)
		test.expected(test.name, r)
	}
}

func BenchmarkLog0(b *testing.B) {
	logger := New(0, io.Discard)
	ctx := context.Background()
	// record allocations regardless of go test -test.bench
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		logger.Errorf(ctx, "i am %s", "fooman")
	}
}

func BenchmarkLog10(b *testing.B) {
	logger := New(10, io.Discard)
	ctx := context.Background()
	// record allocations regardless of go test -test.bench
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		logger.Errorf(ctx, "i am %s", "fooman")
	}
}

func BenchmarkLog10Variadic(b *testing.B) {
	logger := New(10, io.Discard)
	ctx := context.Background()
	// record allocations regardless of go test -test.bench
	b.ReportAllocs()
	for n := 0; n < b.N; n++ {
		logger.Errorf(ctx, "i am %s %s %s %s %s", "fooman", "but", "i", "am", "more")
	}
}
