/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// newSessionProvider creates a session manager for an underlying net.Conn
func newSessionProvider() *sessions {
	return &sessions{known: make(map[SessionID]*sessionContext)}
}

// sessionContext is a thread safe cache that tracks session ids from clients
type sessionContext struct {
	header Header
	Handler
	timer *prometheus.Timer
}

// sessions manages client session ids. we use sessions to know how to
// handle older exchange methods that require multiple packet exchanges
// in reality, this is really only significant for ascii login flows or for
// long running accounting flows.  Per the rfc, sessions are assumed valid
// from the client.
type sessions struct {
	sync.RWMutex
	known map[SessionID]*sessionContext
}

// get a session
func (s *sessions) get(h Header) (Handler, error) {
	if err := ClientSequenceNumber(h.SeqNo).Validate(nil); err != nil {
		s.delete(h.SessionID)
		return nil, fmt.Errorf("sessionID [%v] sequence number is corrupted; %v", h.SessionID, err)
	}
	s.Lock()
	defer s.Unlock()
	sc, ok := s.known[h.SessionID]
	if !ok {
		sessionsGetMiss.Inc()
		return nil, nil
	}
	if err := LastSequence(sc.header.SeqNo).Validate(h.SeqNo); err != nil {
		return nil, fmt.Errorf("sessionID [%v] sequence number is mismatched; %v", h.SessionID, err)
	}
	sessionsGetHit.Inc()
	return sc.Handler, nil
}

// set a session and next handler.  for long running packet exchanges, we need
// to know what handler state was left when we last responded so we know what to
// processes the next client response as.  This is especially important when we
// are using single-connect because we could have multiple packets from multiple
// sessions being multiplexed on one connection.
func (s *sessions) set(h Header, n Handler) {
	s.Lock()
	defer s.Unlock()
	sessionsActive.Inc()
	sessionsSet.Inc()
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		ms := v * 1000 // make milliseconds
		sessionDurations.Observe(ms)
	}))
	s.known[h.SessionID] = &sessionContext{header: h, Handler: n, timer: timer}
}

// update a session id and next handler.
func (s *sessions) update(h Header, n Handler) {
	s.Lock()
	defer s.Unlock()
	sc, ok := s.known[h.SessionID]
	if !ok {
		sessionsGetMiss.Inc()
		return
	}
	sc.header = h
	sc.Handler = n
	s.known[h.SessionID] = sc
}

// delete a session
func (s *sessions) delete(session SessionID) {
	s.Lock()
	defer s.Unlock()
	sessionsActive.Dec()
	if sc := s.known[session]; sc != nil {
		sc.timer.ObserveDuration()
	}
	delete(s.known, session)
}

// close will stop all prom timers, it's the only reason we have this
func (s *sessions) close() {
	for _, r := range s.known {
		r.timer.ObserveDuration()
	}
}

// waitGroup wraps sync.WaitGroup and exposes
// a counter that can be used in Serve()
type waitGroup struct {
	sync.WaitGroup
	active atomic.Int32
}

// Add adds to WaitGroup and increments the count
func (w *waitGroup) Add(delta int) {
	waitgroupActive.Inc()
	w.WaitGroup.Add(delta)
	w.active.Add(1)
}

// Done decrements WaitGroup and the counter
func (w *waitGroup) Done() {
	waitgroupActive.Dec()
	w.WaitGroup.Done()
	w.active.Add(-1)
}
