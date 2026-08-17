/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"bytes"
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// obfuscatedBytes wraps a marshalled body in a packet header of the given
// type, obfuscates it with secret, and returns the wire bytes a client
// would send.
func obfuscatedBytes(t testing.TB, ht HeaderType, body []byte, secret []byte) []byte {
	p := NewPacket(
		SetPacketHeader(NewHeader(
			SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionDefault}),
			SetHeaderType(ht),
			SetHeaderSeqNo(1),
			SetHeaderSessionID(0x1234),
		)),
		SetPacketBody(body),
	)
	require.NoError(t, crypt(secret, p))
	wire, err := p.MarshalBinary()
	require.NoError(t, err)
	return wire
}

// obfuscatedPacketBytes builds a minimal AuthorRequest packet obfuscated
// with the given secret.
func obfuscatedPacketBytes(t testing.TB, secret []byte) []byte {
	body, err := NewAuthorRequest(
		SetAuthorRequestMethod(AuthenMethodTacacsPlus),
		SetAuthorRequestPrivLvl(PrivLvlRoot),
		SetAuthorRequestType(AuthenTypeASCII),
		SetAuthorRequestService(AuthenServiceLogin),
		SetAuthorRequestUser("rotation-test"),
		SetAuthorRequestPort("tty0"),
		SetAuthorRequestRemAddr("10.0.0.1"),
	).MarshalBinary()
	require.NoError(t, err)
	return obfuscatedBytes(t, Authorize, body, secret)
}

func obfuscatedAuthenStartBytes(t testing.TB, secret []byte) []byte {
	body, err := NewAuthenStart(
		SetAuthenStartAction(AuthenActionLogin),
		SetAuthenStartPrivLvl(PrivLvlUser),
		SetAuthenStartType(AuthenTypeASCII),
		SetAuthenStartService(AuthenServiceLogin),
		SetAuthenStartUser("rotation-test"),
		SetAuthenStartPort("tty0"),
		SetAuthenStartRemAddr("10.0.0.1"),
	).MarshalBinary()
	require.NoError(t, err)
	return obfuscatedBytes(t, Authenticate, body, secret)
}

func obfuscatedAcctRequestBytes(t testing.TB, secret []byte) []byte {
	body, err := NewAcctRequest(
		SetAcctRequestFlag(AcctFlagStart),
		SetAcctRequestMethod(AuthenMethodTacacsPlus),
		SetAcctRequestPrivLvl(PrivLvlUser),
		SetAcctRequestType(AuthenTypeASCII),
		SetAcctRequestService(AuthenServiceLogin),
		SetAcctRequestUser("rotation-test"),
		SetAcctRequestPort("tty0"),
		SetAcctRequestRemAddr("10.0.0.1"),
	).MarshalBinary()
	require.NoError(t, err)
	return obfuscatedBytes(t, Accounting, body, secret)
}

func newMultiCrypter(conn net.Conn, primary []byte, alts ...[]byte) *crypter {
	c := newCrypter(primary, conn, false, false)
	c.altSecrets = alts
	return c
}

func TestMultiSecretSelectsAlternate(t *testing.T) {
	secretA := []byte("primary-that-is-wrong")
	secretB := []byte("the-one-the-device-used")

	wire := obfuscatedPacketBytes(t, secretB)
	c := newMultiCrypter(&mockConnection{data: wire}, secretA, secretB)

	got, err := c.read()
	require.NoError(t, err, "read should succeed by falling back to secretB")

	// crypter must have latched onto secretB for the rest of the connection.
	assert.True(t, bytes.Equal(secretB, c.secret), "active secret should be secretB after selection")
	assert.Nil(t, c.altSecrets, "altSecrets cleared after first read")

	// And the de-obfuscated body must round-trip.
	var ar AuthorRequest
	require.NoError(t, Unmarshal(got.Body, &ar))
	assert.Equal(t, AuthenMethodTacacsPlus, ar.Method)
	assert.Equal(t, "rotation-test", string(ar.User))
}

func TestMultiSecretPrimaryUsed(t *testing.T) {
	secretA := []byte("primary")
	secretB := []byte("alt-never-tried")

	wire := obfuscatedPacketBytes(t, secretA)
	c := newMultiCrypter(&mockConnection{data: wire}, secretA, secretB)

	_, err := c.read()
	require.NoError(t, err)
	assert.True(t, bytes.Equal(secretA, c.secret))
	assert.Nil(t, c.altSecrets)
}

func TestMultiSecretAllWrong(t *testing.T) {
	wire := obfuscatedPacketBytes(t, []byte("device-key"))
	c := newMultiCrypter(&mockConnection{data: wire}, []byte("wrong-1"), []byte("wrong-2"))

	_, err := c.read()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bad secret")
}

func TestMultiSecretSinglePathUnchanged(t *testing.T) {
	secret := []byte("only")
	wire := obfuscatedPacketBytes(t, secret)
	c := newCrypter(secret, &mockConnection{data: wire}, false, false)

	_, err := c.read()
	require.NoError(t, err)
	assert.Nil(t, c.altSecrets)
}

func TestBadSecretReplyDoesNotMutateHeader(t *testing.T) {
	h := Header{Type: Authorize, Length: 999, SeqNo: 7}
	var c crypter
	_, err := c.badSecretReply(h)
	require.NoError(t, err)
	assert.EqualValues(t, 999, h.Length, "caller's Header.Length must be untouched")
	assert.EqualValues(t, 7, h.SeqNo, "caller's Header.SeqNo must be untouched")
}

type nopLogger struct{}

func (nopLogger) Infof(context.Context, string, ...interface{})        {}
func (nopLogger) Errorf(context.Context, string, ...interface{})       {}
func (nopLogger) Debugf(context.Context, string, ...interface{})       {}
func (nopLogger) Record(context.Context, map[string]string, ...string) {}

type recordingHandler struct {
	got    chan Request
	cancel context.CancelFunc
}

func (h *recordingHandler) Handle(_ Response, req Request) {
	h.got <- req
	h.cancel() // stop the handle() loop after one packet
}

type multiProvider struct {
	secrets [][]byte
	h       Handler
}

func (m multiProvider) Get(ctx context.Context, remote net.Addr) ([]byte, Handler, error) {
	s, h, err := m.GetSecrets(ctx, remote)
	if len(s) == 0 {
		return nil, h, err
	}
	return s[0], h, err
}

func (m multiProvider) GetSecrets(context.Context, net.Addr) ([][]byte, Handler, error) {
	return m.secrets, m.h, nil
}

type singleProvider struct {
	secret []byte
	h      Handler
}

func (s singleProvider) Get(context.Context, net.Addr) ([]byte, Handler, error) {
	return s.secret, s.h, nil
}

func TestServerServeMultiSecretPath(t *testing.T) {
	secretA := []byte("server-primary-wrong")
	secretB := []byte("server-device-key")

	ctx, cancel := context.WithCancel(context.Background())
	rh := &recordingHandler{got: make(chan Request, 1), cancel: cancel}
	s := NewServer(nopLogger{}, multiProvider{secrets: [][]byte{secretA, secretB}, h: rh})

	mc := &mockConnection{data: obfuscatedPacketBytes(t, secretB)}
	s.Add(1)
	s.serve(ctx, mc)

	select {
	case req := <-rh.got:
		var ar AuthorRequest
		require.NoError(t, Unmarshal(req.Body, &ar))
		assert.Equal(t, "rotation-test", string(ar.User), "alt secret must have been selected and body de-obfuscated")
	default:
		t.Fatal("handler was never invoked; multi-secret path did not reach handle()")
	}
}

func TestServerServeSingleSecretPath(t *testing.T) {
	secret := []byte("only-secret")

	ctx, cancel := context.WithCancel(context.Background())
	rh := &recordingHandler{got: make(chan Request, 1), cancel: cancel}
	s := NewServer(nopLogger{}, singleProvider{secret: secret, h: rh})

	mc := &mockConnection{data: obfuscatedPacketBytes(t, secret)}
	s.Add(1)
	s.serve(ctx, mc)

	select {
	case req := <-rh.got:
		var ar AuthorRequest
		require.NoError(t, Unmarshal(req.Body, &ar))
		assert.Equal(t, "rotation-test", string(ar.User))
	default:
		t.Fatal("handler was never invoked; single-secret fallback path failed")
	}
}

func TestServerServeNoSecretsClosesConn(t *testing.T) {
	s := NewServer(nopLogger{}, multiProvider{secrets: nil, h: nil})
	mc := &mockConnection{}
	s.Add(1)
	s.serve(context.Background(), mc)
	assert.True(t, mc.closed, "serve must close the conn when provider returns no secrets")
}

func TestServerServeNilSecretClosesConn(t *testing.T) {
	// A provider returning a single nil element must be rejected the same as
	// the upstream nil-secret check; a nil key would obfuscate with an empty key.
	h := &recordingHandler{got: make(chan Request, 1)}
	s := NewServer(nopLogger{}, multiProvider{secrets: [][]byte{nil}, h: h})
	mc := &mockConnection{data: obfuscatedPacketBytes(t, []byte("k"))}
	s.Add(1)
	s.serve(context.Background(), mc)
	assert.True(t, mc.closed, "serve must close the conn when provider returns a nil secret")
	assert.Len(t, h.got, 0, "handler must not be invoked")
}

func TestMultiSecretIgnoredOnTLS(t *testing.T) {
	// On the TLS path there is no obfuscation so altSecrets must not be consulted.
	wire := obfuscatedPacketBytes(t, []byte("device-key"))
	// Set the unencrypted flag like a real TLS client would.
	wire[3] |= byte(UnencryptedFlag)
	c := newCrypter([]byte("ignored"), &mockConnection{data: wire}, false, true)
	c.altSecrets = [][]byte{[]byte("also-ignored")}
	_, _ = c.read()
	assert.NotNil(t, c.altSecrets, "TLS path must not consume altSecrets")
}

func TestMultiSecretAcrossPacketTypes(t *testing.T) {
	secretA := []byte("primary-that-is-wrong")
	secretB := []byte("the-one-the-device-used")

	for _, tc := range []struct {
		name string
		wire []byte
	}{
		{"authorize", obfuscatedPacketBytes(t, secretB)},
		{"authenticate", obfuscatedAuthenStartBytes(t, secretB)},
		{"accounting", obfuscatedAcctRequestBytes(t, secretB)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := newMultiCrypter(&mockConnection{data: tc.wire}, secretA, secretB)
			_, err := c.read()
			require.NoError(t, err)
			assert.True(t, bytes.Equal(secretB, c.secret), "alt secret must be selected for %s", tc.name)
		})
	}
}

func FuzzMultiSecretSelection(f *testing.F) {
	f.Add([]byte("primary"), []byte("alternate"))
	f.Add([]byte{0xff, 0x00, 0x7f}, []byte{0x01, 0x02, 0x03, 0x04})
	f.Fuzz(func(t *testing.T, secretA, secretB []byte) {
		if len(secretA) == 0 || len(secretB) == 0 || bytes.Equal(secretA, secretB) {
			t.Skip()
		}
		// clone so the obfuscation pad derivation never aliases the
		// other fuzz input
		a := bytes.Clone(secretA)
		b := bytes.Clone(secretB)
		wire := obfuscatedPacketBytes(t, b)

		// case 1: primary wrong, alt right -> selects b
		c := newMultiCrypter(&mockConnection{data: bytes.Clone(wire)}, a, b)
		if _, err := c.read(); err != nil {
			// detectBadSecret rejected both (false positive on b);
			// pre-existing behaviour, not the alt path
			t.Skip()
		}
		if bytes.Equal(a, c.secret) {
			// detectBadSecret accepted the wrong-key body
			// (no MAC in the obfuscation scheme); upstream would
			// proceed with garbage here too.  Not the alt path.
			t.Skip()
		}
		if !bytes.Equal(b, c.secret) {
			t.Fatalf("primary-wrong: selected secret = %x, want %x", c.secret, b)
		}

		// case 2: primary right, alt unused -> stays b, no fallback
		c = newMultiCrypter(&mockConnection{data: bytes.Clone(wire)}, b, a)
		if _, err := c.read(); err != nil {
			t.Fatalf("primary-right: unexpected read error: %v", err)
		}
		if !bytes.Equal(b, c.secret) {
			t.Fatalf("primary-right: selected secret = %x, want %x (no fallback expected)", c.secret, b)
		}
	})
}

func BenchmarkCrypterReadSingleSecret(b *testing.B) {
	secret := []byte("benchmark-single")
	wire := obfuscatedPacketBytes(b, secret)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := newCrypter(secret, &mockConnection{data: bytes.Clone(wire)}, false, false)
		if _, err := c.read(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCrypterReadWithUnusedAlt(b *testing.B) {
	secret := []byte("benchmark-single")
	alts := [][]byte{[]byte("never-used-because-primary-works")}
	wire := obfuscatedPacketBytes(b, secret)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c := newCrypter(secret, &mockConnection{data: bytes.Clone(wire)}, false, false)
		c.altSecrets = alts
		if _, err := c.read(); err != nil {
			b.Fatal(err)
		}
	}
}
