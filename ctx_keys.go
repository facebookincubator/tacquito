/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.

 Use this file to store context keys
*/

package tacquito

// ContextKey is used in Request contexts
type ContextKey string

// ContextReqID ...
const ContextReqID ContextKey = "reqID"

// ContextSessionID is used to store the context for a session in Request as a wrapped context
const ContextSessionID ContextKey = "session-id"

// ContextConnRemoteAddr is used to store the net.conn remoteAddr within a session.  This value would be present
// in any sub contexts that share the underlying net.conn
const ContextConnRemoteAddr ContextKey = "conn-remote-addr"

// ContextConnLocalAddr is the tacquito server address
const ContextConnLocalAddr ContextKey = "conn-local-addr"

// ContextUser is used to store the username within a session.
const ContextUser ContextKey = "user"

// ContextUserMsg ...
const ContextUserMsg ContextKey = "user-msg"

// ContextRemoteAddr ...
const ContextRemoteAddr ContextKey = "rem-addr"

// ContextReqArgs for logging context arguments with replies
const ContextReqArgs ContextKey = "req-args"

// ContextAcctType ...
const ContextAcctType ContextKey = "type"

// ContextFlags logs the flags attribute of Accounting requests
const ContextFlags ContextKey = "flags"

// ContextPrivLvl ...
const ContextPrivLvl ContextKey = "priv-lvl"

// ContextPort ...
const ContextPort ContextKey = "port"

/* durations
these ctx keys are being stored for request specific tracking of
expensive operations. We already have prometheus Summary metrics tracking
some of timings of these operatings, but they don't expose the level of detail we need
for performance tracking and client debugging
*/

// ContextLoaderDuration is total processing time taken by loader i.e how long
// it takes for the loader to map an IP to a scope
const ContextLoaderDuration ContextKey = "loader_duration_ms"
