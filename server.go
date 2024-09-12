/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Option is used to set optional behaviors on the server. Required behaviors are set
// in NewServer. Omitting options will not adversely affect the service
type Option func(s *Server)

// SetUseProxy will enable ASCII based proxy support defined by
// http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt
func SetUseProxy(v bool) Option {
	return func(s *Server) {
		s.proxy = v
	}
}

// NewServer returns a new server.
// loggerProvider - the logging backend to use
// listener - net.Listener
// sp SecretProvider - enables server to translate net.conn.remaddr into associated config for that device
func NewServer(l loggerProvider, sp SecretProvider, opts ...Option) *Server {
	s := &Server{loggerProvider: l, SecretProvider: sp}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Server  ...
type Server struct {
	loggerProvider
	waitGroup
	SecretProvider

	// enables ha-proxy ascii proxy header support
	proxy bool
}

// DeadlineListener is a net.Listener that supports Deadlines
type DeadlineListener interface {
	net.Listener
	SetDeadline(t time.Time) error
}

// Serve is a blocking method that serves clients
func (s *Server) Serve(ctx context.Context, listener DeadlineListener) error {
	defer func() {
		s.Infof(ctx, "Stopping server listener for %v...", listener.Addr().String())
		err := listener.Close()
		if err != nil {
			s.Errorf(ctx, "%s", err)
		}
		s.Infof(ctx, "waiting for [%v] connections to close prior to shutdown", s.active)
		s.Wait()
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			serveReceived.Inc()
			// the 10 second deadline implies there is a limit to how long downstream handlers
			// may take to respond to a client.  Clients may also give up much sooner than this
			// deadline.  Be mindful of this when adjusting.
			if err := listener.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				s.Errorf(ctx, "cannot set listener deadline; %s", err)
			}
			conn, err := listener.Accept()
			if err != nil {
				var opE *net.OpError
				if errors.As(err, &opE) {
					if !opE.Temporary() {
						serveAcceptedError.Inc()
						return nil
					}
					if opE.Temporary() {
						// triggered by SetDeadline
						continue
					}
					// something else? fall through
				}
				s.Errorf(ctx, "server error in serving request: %s", err)
				serveAcceptedError.Inc()
				continue
			}
			s.Add(1)
			go s.serve(ctx, conn)
		}
	}
}

func (s *Server) serve(ctx context.Context, conn net.Conn) {
	defer s.Done()
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		ms := v * 1000 // make milliseconds
		connectionDuration.Observe(ms)
	}))
	defer timer.ObserveDuration()
	// start a timer to measure loader duration
	loaderStart := time.Now()
	secret, handler, err := s.Get(ctx, conn.RemoteAddr())
	if err != nil || secret == nil || handler == nil {
		s.Errorf(ctx, "ignoring request: %v", err)
		conn.Close()
		timer.ObserveDuration()
		return
	}
	ctx = context.WithValue(ctx, ContextLoaderDuration, time.Since(loaderStart).Milliseconds())
	serveAccepted.Inc()
	s.handle(ctx, newCrypter(secret, conn, s.proxy), handler)
	serveAccepted.Dec()
}

// handle will process connections on a net.Conn. This is meant to be executed in a goroutine
func (s *Server) handle(ctx context.Context, c *crypter, h Handler) {
	// defer closing the connection on return.
	defer c.Close()
	// scoped to the entire undelrying net.Conn.  this is needed for single-connect
	sessionProvider := newSessionProvider()
	defer sessionProvider.close()
	for {
		select {
		case <-ctx.Done():
			s.Debugf(ctx, "context cancellation received, closing connection to %v", c.RemoteAddr())
			return
		default:
			if err := c.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
				s.Errorf(ctx, "unable to set read deadline on connection %v", c.RemoteAddr())
			}
			packet, err := c.read()
			if err != nil {
				if err != io.EOF {
					s.Errorf(ctx, "closing connection, unable to read, %v", err)
				}
				return
			}
			// store basic connection parameters into ctx
			ctxWithAddr := context.WithValue(ctx, ContextConnRemoteAddr, strip(c.RemoteAddr().String()))
			ctxWithAddr = context.WithValue(ctxWithAddr, ContextConnLocalAddr, c.LocalAddr().String())

			// create our request
			req := Request{
				Header:  *packet.Header,
				Body:    packet.Body,
				Context: ctxWithAddr,
			}
			// create the response
			resp := &response{ctx: req.Context, crypter: c, loggerProvider: s.loggerProvider, header: req.Header}
			state, err := sessionProvider.get(req.Header)
			if err != nil {
				s.Errorf(ctx, "unable to obtain a session; connection will close; %v", err)
				return
			}
			// default to our provided handler for new flows
			if state == nil {
				state = h
				sessionProvider.set(req.Header, nil)
			}
			handlers.Inc()
			state.Handle(resp, req)
			handlers.Dec()
			if resp.next == nil {
				s.Debugf(ctx, "[%v] sessionID is complete", req.Header.SessionID)
				sessionProvider.delete(req.Header.SessionID)
				continue
			}
			sessionProvider.update(resp.header, resp.next)
		}
	}
}

// strip removes port and [] from an IP address
// on a best effort basis. In case of any error, the
// original input is returned
func strip(ip string) string {
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		return ip
	}
	return host
}
