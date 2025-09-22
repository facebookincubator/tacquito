/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"sync"
	"testing"
	"time"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/log"

	"github.com/stretchr/testify/assert"
)

func init() {
	rand.Seed(time.Now().UnixNano())
}

func asciiSmasher(sessionID int) Test {
	return Test{
		Name: fmt.Sprintf("authen smasher test [%v]", sessionID),
		Seq: []Sequence{
			{
				Packet: tq.NewPacket(
					tq.SetPacketHeader(
						tq.NewHeader(
							tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
							tq.SetHeaderType(tq.Authenticate),
							tq.SetHeaderSessionID(tq.SessionID(sessionID)),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenStart(
							tq.SetAuthenStartAction(tq.AuthenActionLogin),
							tq.SetAuthenStartPrivLvl(tq.PrivLvlUser),
							tq.SetAuthenStartType(tq.AuthenTypeASCII),
							tq.SetAuthenStartService(tq.AuthenServiceLogin),
						),
					),
				),
				Validate: func(p *tq.Packet) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(p.Body, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetUser {
						return fmt.Errorf("invalid response body for sessionID [%v]", sessionID)
					}
					if p.Header.SeqNo != 2 {
						return fmt.Errorf("invalid sequence number %v != %v", 2, p.Header.SeqNo)
					}
					if p.Header.SessionID != tq.SessionID(sessionID) {
						return fmt.Errorf("invalid session id number %v != %v", sessionID, p.Header.SessionID)
					}
					return nil
				},
			},
			{
				Packet: tq.NewPacket(
					tq.SetPacketHeader(
						tq.NewHeader(
							tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
							tq.SetHeaderType(tq.Authenticate),
							tq.SetHeaderSeqNo(3),
							tq.SetHeaderSessionID(tq.SessionID(sessionID)),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueUserMessage("mr_uses_group"),
						),
					),
				),
				Validate: func(p *tq.Packet) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(p.Body, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetPass {
						return fmt.Errorf("invalid response body for sessionID [%v]", sessionID)
					}
					if p.Header.SeqNo != 4 {
						return fmt.Errorf("invalid sequence number %v != %v", 4, p.Header.SeqNo)
					}
					if p.Header.SessionID != tq.SessionID(sessionID) {
						return fmt.Errorf("invalid session id number %v != %v", sessionID, p.Header.SessionID)
					}
					return nil
				},
			},
			{
				Packet: tq.NewPacket(
					tq.SetPacketHeader(
						tq.NewHeader(
							tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
							tq.SetHeaderType(tq.Authenticate),
							tq.SetHeaderSeqNo(5),
							tq.SetHeaderSessionID(tq.SessionID(sessionID)),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueUserMessage("password"),
						),
					),
				),
				Validate: func(p *tq.Packet) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(p.Body, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusPass {
						return fmt.Errorf("invalid response body for sessionID [%v]", sessionID)
					}
					if p.Header.SeqNo != 6 {
						return fmt.Errorf("invalid sequence number %v != %v", 6, p.Header.SeqNo)
					}
					if p.Header.SessionID != tq.SessionID(sessionID) {
						return fmt.Errorf("invalid session id number %v != %v", sessionID, p.Header.SessionID)
					}
					return nil
				},
			},
		},
	}
}

func authorSmasher(sessionID int) Test {
	return Test{
		Name: fmt.Sprintf("author smasher test [%v]", sessionID),
		Seq: []Sequence{
			{
				Packet: tq.NewPacket(
					tq.SetPacketHeader(
						tq.NewHeader(
							tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
							tq.SetHeaderType(tq.Authorize),
							tq.SetHeaderSessionID(tq.SessionID(sessionID)),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthorRequest(
							tq.SetAuthorRequestMethod(tq.AuthenMethodTacacsPlus),
							tq.SetAuthorRequestPrivLvl(tq.PrivLvlRoot),
							tq.SetAuthorRequestType(tq.AuthenTypeASCII),
							tq.SetAuthorRequestService(tq.AuthenServiceLogin),
							tq.SetAuthorRequestUser("mr_uses_group"),
							tq.SetAuthorRequestArgs(tq.Args{"service=shell", "cmd=configure\n", "cmd-arg=terminal\n", "cmd-arg=<cr>"}),
						),
					),
				),
				Validate: func(p *tq.Packet) error {
					var body tq.AuthorReply
					if err := tq.Unmarshal(p.Body, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthorStatusPassAdd {
						return fmt.Errorf("invalid response body for sessionID [%v]", sessionID)
					}
					if p.Header.SeqNo != 2 {
						return fmt.Errorf("invalid sequence number %v != %v", 2, p.Header.SeqNo)
					}
					if p.Header.SessionID != tq.SessionID(sessionID) {
						return fmt.Errorf("invalid session id number %v != %v", sessionID, p.Header.SessionID)
					}
					return nil
				},
			},
		},
	}
}

func acctSmasher(sessionID int) Test {
	var f tq.AcctRequestFlag
	f.Set(tq.AcctFlagStart)
	return Test{
		Name: fmt.Sprintf("acct smasher test [%v]", sessionID),
		Seq: []Sequence{
			{
				Packet: tq.NewPacket(
					tq.SetPacketHeader(
						tq.NewHeader(
							tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
							tq.SetHeaderType(tq.Accounting),
							tq.SetHeaderSessionID(tq.SessionID(sessionID)),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAcctRequest(
							tq.SetAcctRequestFlag(f),
							tq.SetAcctRequestMethod(tq.AuthenMethodTacacsPlus),
							tq.SetAcctRequestPrivLvl(tq.PrivLvlRoot),
							tq.SetAcctRequestType(tq.AuthenTypeASCII),
							tq.SetAcctRequestService(tq.AuthenServiceLogin),
							tq.SetAcctRequestUser("mr_uses_group"),
							tq.SetAcctRequestArgs(tq.Args{"cmd=show", "cmd-arg=system"}),
						),
					),
				),
				Validate: func(p *tq.Packet) error {
					var body tq.AcctReply
					if err := tq.Unmarshal(p.Body, &body); err != nil {
						return err
					}
					if body.Status != tq.AcctReplyStatusSuccess {
						return fmt.Errorf("invalid response body for sessionID [%v]", sessionID)
					}
					if p.Header.SeqNo != 2 {
						return fmt.Errorf("invalid sequence number %v != %v", 2, p.Header.SeqNo)
					}
					if p.Header.SessionID != tq.SessionID(sessionID) {
						return fmt.Errorf("invalid session id number %v != %v", sessionID, p.Header.SessionID)
					}
					return nil
				},
			},
		},
	}
}

func TestSurge(t *testing.T) {
	logger := log.New(30, io.Discard)
	ctx := context.Background()
	sp, err := MockSecretProvider(ctx, logger, "testdata/test_config.yaml")
	assert.NoError(t, err)

	listener, err := net.Listen("tcp6", "[::1]:0")
	assert.NoError(t, err)
	tcpListener := listener.(*net.TCPListener)

	s := tq.NewServer(logger, sp)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := s.Serve(ctx, tcpListener); err != nil {
			assert.NoError(t, err)
		}
	}()

	// number of sessions to create
	maxSession := 1500
	// use a map to randomize session entry
	tests := map[int]Test{}
	for i := 1; i <= maxSession; i += 3 {
		tests[i] = asciiSmasher(i)
		tests[i+1] = authorSmasher(i + 1)
		tests[i+2] = acctSmasher(i + 2)
	}

	// number of clients to create
	numberOfClients := 75
	queue := make(chan Test, numberOfClients)
	do := func(ctest <-chan Test, wg *sync.WaitGroup) {
		c, err := tq.NewClient(tq.SetClientDialer("tcp6", listener.Addr().String(), []byte("fooman")))
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("%v", err))
		}
		go func() {
			defer c.Close()
			max := 1000
			min := 1
			ticker := time.NewTicker(time.Duration(rand.Intn(max-min)+min) * time.Millisecond)
			for ct := range ctest {
				// artificial delay
				<-ticker.C
				for _, s := range ct.Seq {
					resp, err := c.Send(s.Packet)
					assert.NoError(t, err)
					err = s.Validate(resp)
					assert.NoError(t, err)
				}
			}
			wg.Done()
		}()
	}
	var wg sync.WaitGroup
	for i := 0; i < numberOfClients; i++ {
		wg.Add(1)
		do(queue, &wg)
	}
	for _, ctest := range tests {
		queue <- ctest
	}
	close(queue)
	wg.Wait()
}

func TestSurgeTLS(t *testing.T) {
	testDir := t.TempDir()
	_, _, serverTLSConfig, err := GenerateTLSCertificate(testDir)
	assert.NoError(t, err)

	logger := log.New(30, io.Discard)
	ctx := context.Background()
	sp, err := MockSecretProvider(ctx, logger, "testdata/test_config.yaml")
	assert.NoError(t, err)

	// Create TLS listener
	listener, err := net.Listen("tcp6", "[::1]:0")
	assert.NoError(t, err)
	tlsListener, err := tq.NewTLSListener(listener, serverTLSConfig)
	assert.NoError(t, err)

	s := tq.NewServer(logger, sp, tq.SetUseTLS(true))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		if err := s.Serve(ctx, tlsListener); err != nil {
			assert.NoError(t, err)
		}
	}()

	// Client TLS config (with insecure skip verify for test certificates)
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: true,
	}

	// number of sessions to create
	maxSession := 1500
	// use a map to randomize session entry
	tests := map[int]Test{}
	for i := 1; i <= maxSession; i += 3 {
		tests[i] = asciiSmasher(i)
		tests[i+1] = authorSmasher(i + 1)
		tests[i+2] = acctSmasher(i + 2)
	}

	// number of clients to create
	numberOfClients := 75
	queue := make(chan Test, numberOfClients)
	do := func(ctest <-chan Test, wg *sync.WaitGroup) {
		c, err := tq.NewClient(tq.SetClientTLSDialer("tcp6", listener.Addr().String(), clientTLSConfig))
		if err != nil {
			assert.FailNow(t, fmt.Sprintf("%v", err))
		}
		go func() {
			defer c.Close()
			max := 1000
			min := 1
			ticker := time.NewTicker(time.Duration(rand.Intn(max-min)+min) * time.Millisecond)
			for ct := range ctest {
				// artificial delay
				<-ticker.C
				for _, s := range ct.Seq {
					resp, err := c.Send(s.Packet)
					assert.NoError(t, err)
					err = s.Validate(resp)
					assert.NoError(t, err)
				}
			}
			wg.Done()
		}()
	}
	var wg sync.WaitGroup
	for i := 0; i < numberOfClients; i++ {
		wg.Add(1)
		do(queue, &wg)
	}
	for _, ctest := range tests {
		queue <- ctest
	}
	close(queue)
	wg.Wait()
}
