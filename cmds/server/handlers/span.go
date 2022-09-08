/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package handlers

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/config"

	"github.com/prometheus/client_golang/prometheus"
)

const (
	// this is the tcp connection idle timeout. It will act as a initial deadline on the
	// tcp conn, and the conn Write deadline is reset to this value on every successful write
	idleTimeout = 5 * time.Second
)

// NewSpan ...
func NewSpan(l loggerProvider) *Span {
	return &Span{loggerProvider: l}
}

// Span is the main entry point for incoming aaa messages from clients.
type Span struct {
	loggerProvider
	configProvider
	ctx         context.Context
	destination string
	switchAddr  string
	remAddr     string
	packetType  tq.HeaderType
}

func strToHeaderType(packetType string) tq.HeaderType {
	packetType = strings.ToLower(packetType)
	switch packetType {
	case "authenticate":
		return tq.Authenticate
	case "authorize":
		return tq.Authorize
	case "accounting":
		return tq.Accounting
	}
	return 0
}

// New ...
func (s *Span) New(ctx context.Context, c config.Provider, options map[string]string) tq.Handler {
	destination, ok := options["destination"]
	if !ok {
		s.Errorf(ctx, "Unable to find key destination in handler options")
		return nil
	}
	return &Span{
		loggerProvider: s.loggerProvider,
		ctx:            ctx,
		configProvider: c, destination: destination,
		switchAddr: options["switchAddr"],
		remAddr:    options["remAddr"],
		packetType: strToHeaderType(options["packetType"]),
	}
}

type writer struct {
	loggerProvider
	net.Conn
	ctx        context.Context
	switchAddr string
	remAddr    string
	packetType tq.HeaderType
}

// Write sends the req/response from client/server to span host
// after filtering on fields inside the packet
// currently supported fields are rem-addr(remote-host), switchAddr(switch to which user is trying to login to)
// and packet-Type (authenticate/authorise/accounting)
func (w writer) Write(p []byte) (int, error) {
	if w.Conn == nil {
		spanHandleWriteError.Inc()
		w.Errorf(w.ctx, "connection object attached to writer is invalid")
		return 0, fmt.Errorf("inactive connection object")
	}
	remoteAddr := w.RemoteAddr().String()
	if w.switchAddr != "" && remoteAddr != w.switchAddr {
		spanHandleWriteError.Inc()
		s := fmt.Sprintf("Skipping packet, switchAddr don't match, actual addr %v vs configured addr %v", remoteAddr, w.switchAddr)
		w.Errorf(w.ctx, s)
		return 0, fmt.Errorf(s)
	}
	packet := tq.NewPacket()
	packet.UnmarshalBinary(p)
	if w.packetType != 0 && packet.Header.Type != w.packetType {
		spanHandleWriteError.Inc()
		s := fmt.Sprintf("Skipping packet, Packet types don't match, actual type %v vs configured type %v", packet.Header.Type, w.packetType)
		w.Errorf(w.ctx, s)
		return 0, fmt.Errorf(s)
	}
	if w.remAddr != "" {
		req := tq.Request{Header: *packet.Header, Body: packet.Body[:]}
		fields := req.Fields()
		remAddrField, found := fields["rem-addr"]
		if found && remAddrField != w.remAddr {
			spanHandleWriteError.Inc()
			s := fmt.Sprintf("Skipping packet, client IPs don't match, actual client IP %v vs configured IP %v", remAddrField, w.remAddr)
			w.Errorf(w.ctx, s)
			return 0, fmt.Errorf(s)
		}
	}
	n, err := w.Conn.Write(p)
	if err != nil {
		spanHandleWriteError.Inc()
		return n, err
	}
	// successful write, let's increase the idletimeout
	w.Infof(w.ctx, "Wrote %v bytes to connection", n)
	w.SetWriteDeadline(time.Now().Add(idleTimeout))
	spanHandleWriteSuccess.Inc()
	return n, err
}

func (s *Span) dialHost() (net.Conn, error) {
	c, err := net.Dial("tcp6", s.destination)
	if err != nil {
		return nil, fmt.Errorf("couldn't dial the connection to %v due to error %v", s.destination, err)
	}
	s.Infof(s.ctx, "Dialled a tcp connection to host %v", s.destination)
	return c, nil
}

// Handle ...
func (s *Span) Handle(response tq.Response, request tq.Request) {
	spanHandle.Inc()
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		ms := v * 1000 // make milliseconds
		spanDurations.Observe(ms)
	}))
	start := time.Now()
	conn, err := s.dialHost()
	callNextHandler := func() {
		nextHandler := NewStart(s.loggerProvider).New(request.Context, s.configProvider.(config.Provider), nil)
		nextHandler.Handle(response, request)
	}
	if err != nil {
		spanHandleError.Inc()
		s.Errorf(request.Context, "Unable to span connection due to error %v", err)
		callNextHandler()
		return
	}
	conn.SetWriteDeadline(time.Now().Add(idleTimeout))
	w := &writer{loggerProvider: s.loggerProvider,
		Conn:       conn,
		ctx:        request.Context,
		remAddr:    s.remAddr,
		switchAddr: s.switchAddr,
		packetType: s.packetType,
	}
	// Write the request to the connection
	req := tq.Packet{
		Header: &request.Header,
		Body:   request.Body[:],
	}
	reqBytes, err := req.MarshalBinary()
	if err != nil {
		s.Infof(request.Context, "unable to write request to connection due to error %v. Skipping packet...", err)
		callNextHandler()
		return
	}
	w.Write(reqBytes)
	// Write responses
	go func() {
		for range request.Context.Done() {
			duration := time.Since(start)
			timer.ObserveDuration()
			s.Infof(request.Context, "Request context cancelled, total duration of connection %v", duration)
			w.Close()
			return
		}
	}()
	response.RegisterWriter(w)
	callNextHandler()
}
