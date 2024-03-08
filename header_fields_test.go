/*
Copyright (c) Facebook, Inc. and its affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
*/
package tacquito

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSequenceNumber(t *testing.T) {
	tests := []struct {
		name     string
		validate func()
	}{
		{
			name: "below lower bound",
			validate: func() {
				err := SequenceNumber(0).Validate(nil)
				assert.Error(t, err, "sequence 0 should be invalid")
			},
		},
		{
			name: "lower bound",
			validate: func() {
				err := SequenceNumber(1).Validate(nil)
				assert.NoError(t, err, "sequence 1 should be valid")
			},
		},
		{
			name: "upper bound",
			validate: func() {
				err := SequenceNumber(HeaderMaxSequence).Validate(nil)
				assert.NoError(t, err, "sequence value of 2 ^ 8 - 1 should be valid")
			},
		},
		{
			name: "beyond upper bound",
			validate: func() {
				err := SequenceNumber(HeaderMaxSequence + 1).Validate(nil)
				assert.Error(t, err, "sequence number beyond 2 ^ 8 - 1 should be invalid")
			},
		},
		{
			name: "invalid client sequence",
			validate: func() {
				err := ClientSequenceNumber(2).Validate(nil)
				assert.Error(t, err, "even sequence number should be invalid")
			},
		},
		{
			name: "invalid exchange sequence",
			validate: func() {
				last := SequenceNumber(4)
				current := SequenceNumber(3)
				err := LastSequence(last).Validate(current)
				assert.Error(t, err, "sequence numbers must be monotonic")
			},
		},
	}

	for _, test := range tests {
		test.validate()
	}
}
