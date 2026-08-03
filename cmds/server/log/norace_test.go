//go:build !race

/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package log

// raceEnabled reports whether this test binary was built with the race
// detector. See race_test.go for the instrumented value.
const raceEnabled = false
