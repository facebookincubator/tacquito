/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
)

// mockConnection is a mock implementation of net.Conn for testing
type mockConnection struct {
	data   []byte
	closed bool
}

func (m *mockConnection) Read(b []byte) (n int, err error) {
	if len(m.data) == 0 {
		return 0, fmt.Errorf("no data")
	}
	n = copy(b, m.data)
	m.data = m.data[n:]
	return n, nil
}

func (m *mockConnection) Write(b []byte) (n int, err error) {
	if m.closed {
		return 0, fmt.Errorf("connection closed")
	}
	m.data = append(m.data, b...)
	return len(b), nil
}

func (m *mockConnection) Close() error {
	m.closed = true
	return nil
}

func (m *mockConnection) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 49}
}

func (m *mockConnection) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *mockConnection) SetDeadline(t time.Time) error      { return nil }
func (m *mockConnection) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConnection) SetWriteDeadline(t time.Time) error { return nil }

// returns an encrypted TACACs+ packet's byte values, contains the 12 byte header
// encrypted with secret []byte("fooman")
func getEncryptedBytes() []byte {
	return []byte{0xc1, 0x01, 0x01, 0x00, 0x00, 0x00, 0x30, 0x39, 0x00, 0x00, 0x00, 0x2c, 0x9c, 0xed, 0x73,
		0xaa, 0x3d, 0x6d, 0x2f, 0x1f, 0xef, 0x62, 0x98, 0x73, 0xf0, 0xac, 0x2f, 0x11, 0x8a, 0xe2, 0x89, 0x8a,
		0xcb, 0x50, 0x72, 0xb2, 0x6d, 0xd2, 0xec, 0xab, 0xe1, 0x4e, 0x22, 0x64, 0x4c, 0x7c, 0xb2, 0xe, 0x43,
		0xe, 0x33, 0x92, 0x85, 0x47, 0xca, 0xfc}
}

// returns a decrypted TACACs+ packet's byte values, does NOT contain the 12 byte header
func getDecryptedBytes() []byte {
	return []byte{0x01, 0x01, 0x01, 0x01, 0x05, 0x0B, 0x14, 0x00, 0x61, 0x64, 0x6D, 0x69, 0x6E, 0x63, 0x6F,
		0x6D, 0x6D, 0x61, 0x6E, 0x64, 0x2D, 0x61, 0x70, 0x69, 0x32, 0x30, 0x30, 0x31, 0x3A, 0x34, 0x38,
		0x36, 0x30, 0x3A, 0x34, 0x38, 0x36, 0x30, 0x3A, 0x3A, 0x38, 0x38, 0x38, 0x38}
}

func TestDecrypt(t *testing.T) {
	encrypted := getEncryptedBytes()
	decrypted := getDecryptedBytes()
	var header Header
	err := Unmarshal(encrypted[:12], &header)
	assert.NoError(t, err)
	packet := &Packet{Header: &header, Body: encrypted[12:]}

	err = crypt([]byte("fooman"), packet)
	assert.NoError(t, err)

	assert.Equal(t, decrypted, packet.Body)
	var body AuthenStart
	err = Unmarshal(packet.Body, &body)
	assert.NoError(t, err)
	t.Log(spew.Sdump(body))
}

func TestEncrypt(t *testing.T) {
	encrypted := getEncryptedBytes()
	decrypted := getDecryptedBytes()

	body, _ := NewAuthenStart(
		SetAuthenStartAction(AuthenActionLogin),
		SetAuthenStartPrivLvl(PrivLvlUser),
		SetAuthenStartType(AuthenTypeASCII),
		SetAuthenStartService(AuthenServiceLogin),
		SetAuthenStartUser("admin"),
		SetAuthenStartPort("command-api"),
		SetAuthenStartRemAddr("2001:4860:4860::8888"),
	).MarshalBinary()

	packet := NewPacket(
		SetPacketHeader(
			NewHeader(
				SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
				SetHeaderType(Authenticate),
				SetHeaderSessionID(12345),
			),
		),
		SetPacketBody(body),
	)
	t.Log(spew.Sdump(packet))
	err := crypt([]byte("fooman"), packet)
	assert.NoError(t, err)
	t.Log(spew.Sdump(packet))
	assert.Equal(t, encrypted[12:], packet.Body)
	err = crypt([]byte("fooman"), packet)
	assert.NoError(t, err)
	t.Log(spew.Sdump(packet))
	assert.Equal(t, decrypted, packet.Body)
}

func TestEncryptDecryptSecretMismatch(t *testing.T) {
	body := NewAuthenReply(
		SetAuthenReplyStatus(AuthenStatusGetUser),
		SetAuthenReplyServerMsg("\nUser Access Verification\n\nUsername:"),
	)
	b, _ := body.MarshalBinary()

	packet := NewPacket(
		SetPacketHeader(
			NewHeader(
				SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
				SetHeaderType(Authenticate),
				SetHeaderSessionID(12345),
			),
		),
		SetPacketBody(b),
	)

	secret := []byte("chilled cow")
	err := crypt(secret, packet)
	assert.NoError(t, err)

	// We need to ensure Encrypt and Decrypt operations result in an error if a secret mismatches
	// ensure secret mismatch causes an error
	secret = []byte("imma bad secret")
	err = crypt(secret, packet)
	assert.NoError(t, err)

	// Unmarshal decrypted bytes back into original packet body type
	// this should cause a malformed packet error because of a secret mismatch when encrypt/decrypt
	newAuthenReply := &AuthenReply{}
	err = newAuthenReply.UnmarshalBinary(packet.Body)
	assert.Error(t, err, "a bad secret change should have caused this packet to be malformed")
	assert.NotEqual(t, *body, *newAuthenReply)
}

func TestPacketEncryptDecryptUnencryptFlagSet(t *testing.T) {
	body := NewAuthenReply(
		SetAuthenReplyStatus(AuthenStatusGetUser),
		SetAuthenReplyServerMsg("\nUser Access Verification\n\nUsername:"),
	)
	b, _ := body.MarshalBinary()

	packet := NewPacket(
		SetPacketHeader(
			NewHeader(
				SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
				SetHeaderType(Authenticate),
				SetHeaderFlag(UnencryptedFlag),
				SetHeaderSessionID(12345),
			),
		),
		SetPacketBody(b),
	)

	secret := []byte("chilled cow")

	err := crypt(secret, packet)
	assert.NoError(t, err)
	assert.Equal(t, b, packet.Body)

	err = crypt(secret, packet)
	assert.NoError(t, err)
	assert.Equal(t, b, packet.Body)
}

// benchTest is used for allocation testing
type benchTest struct {
	name     string
	fn       func(b *testing.B)
	expected func(name string, r testing.BenchmarkResult)
}

func TestCrypterAllocation(t *testing.T) {
	tests := []benchTest{
		{
			name: "encrypt",
			fn:   BenchmarkCrypterAllocation,
			expected: func(name string, r testing.BenchmarkResult) {
				t.Log(spew.Sdump(r))
				expectedAllocs := 4
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

// BenchmarkCrypterAllocation benchmarks the allocs/op crypter takes when called with crypted
// or decrypted bytes.  Since the op is the same in both directions we only test one form of it
func BenchmarkCrypterAllocation(b *testing.B) {
	encrypted := getEncryptedBytes()
	var header Header
	Unmarshal(encrypted[:12], &header)
	packet := &Packet{Header: &header, Body: encrypted[12:]}
	secret := []byte("fooman")

	// record allocations regardless of go test -test.bench
	b.ReportAllocs()
	for range b.N {
		crypt(secret, packet)
	}
}

// TestUnsetFlagReplyAuthenticate tests the unsetFlagReply function for authentication packets
func TestUnsetFlagReplyAuthenticate(t *testing.T) {
	c := &crypter{tls: true}
	header := NewHeader(
		SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
		SetHeaderType(Authenticate),
		SetHeaderSessionID(12345),
		SetHeaderSeqNo(5),
	)

	reply, err := c.unsetFlagReply(header)
	assert.NoError(t, err)
	assert.NotNil(t, reply)

	// Verify the header flags and sequence number have been properly set
	assert.True(t, reply.Header.Flags.Has(UnencryptedFlag))
	assert.Equal(t, SequenceNumber(1), reply.Header.SeqNo)

	// Verify the body contains the expected error response
	var authenReply AuthenReply
	err = Unmarshal(reply.Body, &authenReply)
	assert.NoError(t, err)
	assert.Equal(t, AuthenStatusError, authenReply.Status)
	assert.Equal(t, AuthenServerMsg("unencrypted flag not set"), authenReply.ServerMsg)
}

// TestUnsetFlagReplyAuthorize tests the unsetFlagReply function for authorization packets
func TestUnsetFlagReplyAuthorize(t *testing.T) {
	c := &crypter{tls: true}
	header := NewHeader(
		SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
		SetHeaderType(Authorize),
		SetHeaderSessionID(12345),
		SetHeaderSeqNo(5),
	)

	reply, err := c.unsetFlagReply(header)
	assert.NoError(t, err)
	assert.NotNil(t, reply)

	// Verify the header flags and sequence number have been properly set
	assert.True(t, reply.Header.Flags.Has(UnencryptedFlag))
	assert.Equal(t, SequenceNumber(1), reply.Header.SeqNo)

	// Verify the body contains the expected error response
	var authorReply AuthorReply
	err = Unmarshal(reply.Body, &authorReply)
	assert.NoError(t, err)
	assert.Equal(t, AuthorStatusError, authorReply.Status)
	assert.Equal(t, AuthorServerMsg("unencrypted flag not set"), authorReply.ServerMsg)
}

// TestUnsetFlagReplyAccounting tests the unsetFlagReply function for accounting packets
func TestUnsetFlagReplyAccounting(t *testing.T) {
	c := &crypter{tls: true}
	header := NewHeader(
		SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
		SetHeaderType(Accounting),
		SetHeaderSessionID(12345),
		SetHeaderSeqNo(5),
	)

	reply, err := c.unsetFlagReply(header)
	assert.NoError(t, err)
	assert.NotNil(t, reply)

	// Verify the header flags and sequence number have been properly set
	assert.True(t, reply.Header.Flags.Has(UnencryptedFlag))
	assert.Equal(t, SequenceNumber(1), reply.Header.SeqNo)

	// Verify the body contains the expected error response
	var acctReply AcctReply
	err = Unmarshal(reply.Body, &acctReply)
	assert.NoError(t, err)
	assert.Equal(t, AcctReplyStatusError, acctReply.Status)
	assert.Equal(t, AcctServerMsg("unencrypted flag not set"), acctReply.ServerMsg)
}

// TestUnsetFlagReplyInvalidType tests the unsetFlagReply function with an invalid header type
func TestUnsetFlagReplyInvalidType(t *testing.T) {
	c := &crypter{tls: true}
	header := NewHeader(
		SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
		SetHeaderType(HeaderType(99)), // Invalid type
		SetHeaderSessionID(12345),
	)

	reply, err := c.unsetFlagReply(header)
	assert.Error(t, err)
	assert.Nil(t, reply)
	assert.Contains(t, err.Error(), "unknown header type")
}

// TestBadSecretReplyAuthenticate tests the badSecretReply function for authentication packets
func TestBadSecretReplyAuthenticate(t *testing.T) {
	c := &crypter{}
	header := NewHeader(
		SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
		SetHeaderType(Authenticate),
		SetHeaderSessionID(12345),
		SetHeaderSeqNo(5),
	)

	reply, err := c.badSecretReply(header)
	assert.NoError(t, err)
	assert.NotNil(t, reply)

	// Verify the sequence number has been reset
	assert.Equal(t, SequenceNumber(1), reply.Header.SeqNo)

	// Verify the body contains the expected error response
	var authenReply AuthenReply
	err = Unmarshal(reply.Body, &authenReply)
	assert.NoError(t, err)
	assert.Equal(t, AuthenStatusError, authenReply.Status)
	assert.Equal(t, AuthenServerMsg("bad secret"), authenReply.ServerMsg)
}

// TestBadSecretReplyAuthorize tests the badSecretReply function for authorization packets
func TestBadSecretReplyAuthorize(t *testing.T) {
	c := &crypter{}
	header := NewHeader(
		SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
		SetHeaderType(Authorize),
		SetHeaderSessionID(12345),
		SetHeaderSeqNo(5),
	)

	reply, err := c.badSecretReply(header)
	assert.NoError(t, err)
	assert.NotNil(t, reply)

	// Verify the sequence number has been reset
	assert.Equal(t, SequenceNumber(1), reply.Header.SeqNo)

	// Verify the body contains the expected error response
	var authorReply AuthorReply
	err = Unmarshal(reply.Body, &authorReply)
	assert.NoError(t, err)
	assert.Equal(t, AuthorStatusError, authorReply.Status)
	assert.Equal(t, AuthorServerMsg("bad secret"), authorReply.ServerMsg)
}

// TestBadSecretReplyAccounting tests the badSecretReply function for accounting packets
func TestBadSecretReplyAccounting(t *testing.T) {
	c := &crypter{}
	header := NewHeader(
		SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
		SetHeaderType(Accounting),
		SetHeaderSessionID(12345),
		SetHeaderSeqNo(5),
	)

	reply, err := c.badSecretReply(header)
	assert.NoError(t, err)
	assert.NotNil(t, reply)

	// Verify the sequence number has been reset
	assert.Equal(t, SequenceNumber(1), reply.Header.SeqNo)

	// Verify the body contains the expected error response
	var acctReply AcctReply
	err = Unmarshal(reply.Body, &acctReply)
	assert.NoError(t, err)
	assert.Equal(t, AcctReplyStatusError, acctReply.Status)
	assert.Equal(t, AcctServerMsg("bad secret"), acctReply.ServerMsg)
}

// TestBadSecretReplyInvalidType tests the badSecretReply function with an invalid header type
func TestBadSecretReplyInvalidType(t *testing.T) {
	c := &crypter{}
	header := NewHeader(
		SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
		SetHeaderType(HeaderType(99)), // Invalid type
		SetHeaderSessionID(12345),
	)

	reply, err := c.badSecretReply(header)
	assert.Error(t, err)
	assert.Nil(t, reply)
	assert.Contains(t, err.Error(), "unknown header type")
}

// TestNewCrypterWithTLS tests creating a new crypter with TLS enabled
func TestNewCrypterWithTLS(t *testing.T) {
	secret := []byte("test-secret")
	mockConn := &mockConnection{}

	// Test creating crypter without TLS
	c := newCrypter(secret, mockConn, false, false)
	assert.Equal(t, secret, c.secret)
	assert.Equal(t, mockConn, c.Conn)
	assert.False(t, c.proxy)
	assert.False(t, c.tls)

	// Test creating crypter with proxy enabled
	c = newCrypter(secret, mockConn, false, true)
	assert.True(t, c.tls)
	assert.False(t, c.proxy)
}

// TestCrypterWriteTLS tests the write method behavior with TLS enabled
func TestCrypterWriteTLS(t *testing.T) {
	mockConn := &mockConnection{}
	c := &crypter{
		secret: []byte("test-secret"),
		Conn:   mockConn,
		tls:    true,
	}

	body := NewAuthenReply(
		SetAuthenReplyStatus(AuthenStatusGetUser),
		SetAuthenReplyServerMsg("Username:"),
	)
	b, _ := body.MarshalBinary()

	packet := NewPacket(
		SetPacketHeader(
			NewHeader(
				SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
				SetHeaderType(Authenticate),
				SetHeaderSessionID(12345),
			),
		),
		SetPacketBody(b),
	)

	// Initially, the packet should not have the UnencryptedFlag set
	assert.False(t, packet.Header.Flags.Has(UnencryptedFlag))

	n, err := c.write(packet)
	assert.NoError(t, err)
	assert.Greater(t, n, 0)

	// After write with TLS enabled, the UnencryptedFlag should be set
	assert.True(t, packet.Header.Flags.Has(UnencryptedFlag))
}

// TestCrypterWriteNonTLS tests the write method behavior with TLS disabled
func TestCrypterWriteNonTLS(t *testing.T) {
	mockConn := &mockConnection{}
	c := &crypter{
		secret: []byte("test-secret"),
		Conn:   mockConn,
		tls:    false,
	}

	body := NewAuthenReply(
		SetAuthenReplyStatus(AuthenStatusGetUser),
		SetAuthenReplyServerMsg("Username:"),
	)
	b, _ := body.MarshalBinary()

	packet := NewPacket(
		SetPacketHeader(
			NewHeader(
				SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
				SetHeaderType(Authenticate),
				SetHeaderSessionID(12345),
			),
		),
		SetPacketBody(b),
	)

	// Store original body for comparison
	originalBody := make([]byte, len(packet.Body))
	copy(originalBody, packet.Body)

	n, err := c.write(packet)
	assert.NoError(t, err)
	assert.Greater(t, n, 0)

	// For non-TLS connections, the body should be encrypted (different from original)
	assert.NotEqual(t, originalBody, packet.Body)
	// UnencryptedFlag should not be set
	assert.False(t, packet.Header.Flags.Has(UnencryptedFlag))
}

// TestCrypterWriteNilPacket tests the write method with nil packet
func TestCrypterWriteNilPacket(t *testing.T) {
	mockConn := &mockConnection{}
	c := &crypter{
		secret: []byte("test-secret"),
		Conn:   mockConn,
		tls:    false,
	}

	n, err := c.write(nil)
	assert.Error(t, err)
	assert.Equal(t, 0, n)
	assert.Contains(t, err.Error(), "packet cannot be nil")
}

// TestCrypterWriteNilBody tests the write method with nil packet body
func TestCrypterWriteNilBody(t *testing.T) {
	mockConn := &mockConnection{}
	c := &crypter{
		secret: []byte("test-secret"),
		Conn:   mockConn,
		tls:    false,
	}

	packet := NewPacket(
		SetPacketHeader(
			NewHeader(
				SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
				SetHeaderType(Authenticate),
				SetHeaderSessionID(12345),
			),
		),
		SetPacketBody(nil),
	)

	n, err := c.write(packet)
	assert.Error(t, err)
	assert.Equal(t, 0, n)
	assert.Contains(t, err.Error(), "packet.Body cannot be nil")
}

// TestCrypterReadTLSWithUnencryptedFlag tests the read method with TLS enabled and UnencryptedFlag set
func TestCrypterReadTLSWithUnencryptedFlag(t *testing.T) {
	// Create a valid TACACS+ packet with UnencryptedFlag set
	body := NewAuthenStart(
		SetAuthenStartAction(AuthenActionLogin),
		SetAuthenStartPrivLvl(PrivLvlUser),
		SetAuthenStartType(AuthenTypeASCII),
		SetAuthenStartService(AuthenServiceLogin),
		SetAuthenStartUser("admin"),
		SetAuthenStartPort("command-api"),
		SetAuthenStartRemAddr("127.0.0.1"),
	)
	b, _ := body.MarshalBinary()

	packet := NewPacket(
		SetPacketHeader(
			NewHeader(
				SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
				SetHeaderType(Authenticate),
				SetHeaderFlag(UnencryptedFlag), // Set the flag for TLS
				SetHeaderSessionID(12345),
			),
		),
		SetPacketBody(b),
	)

	// Marshal the entire packet to bytes
	packetBytes, err := packet.MarshalBinary()
	assert.NoError(t, err)

	// Create mock connection with the packet data
	mockConn := &mockConnection{data: packetBytes}
	c := &crypter{
		secret: []byte("test-secret"),
		Conn:   mockConn,
		Reader: bufio.NewReader(mockConn),
		tls:    true,
	}

	// Read the packet
	readPacket, err := c.read()
	assert.NoError(t, err)
	assert.NotNil(t, readPacket)

	// Verify the packet was read correctly
	assert.Equal(t, Authenticate, readPacket.Header.Type)
	assert.True(t, readPacket.Header.Flags.Has(UnencryptedFlag))
	assert.Equal(t, SessionID(12345), readPacket.Header.SessionID)

	// Verify the body can be unmarshaled correctly
	var readBody AuthenStart
	err = Unmarshal(readPacket.Body, &readBody)
	assert.NoError(t, err)
	assert.Equal(t, AuthenUser("admin"), readBody.User)
}

// TestCrypterReadTLSWithoutUnencryptedFlag tests the read method with TLS enabled but UnencryptedFlag not set
func TestCrypterReadTLSWithoutUnencryptedFlag(t *testing.T) {
	// Capture the counter value before the test
	counterBefore := testutil.ToFloat64(crypterReadFlagError)

	// Create a valid TACACS+ packet WITHOUT UnencryptedFlag set
	body := NewAuthenStart(
		SetAuthenStartAction(AuthenActionLogin),
		SetAuthenStartPrivLvl(PrivLvlUser),
		SetAuthenStartType(AuthenTypeASCII),
		SetAuthenStartService(AuthenServiceLogin),
		SetAuthenStartUser("admin"),
		SetAuthenStartPort("command-api"),
		SetAuthenStartRemAddr("127.0.0.1"),
	)
	b, _ := body.MarshalBinary()

	packet := NewPacket(
		SetPacketHeader(
			NewHeader(
				SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
				SetHeaderType(Authenticate),
				// UnencryptedFlag is NOT set - this should trigger an error response
				SetHeaderSessionID(12345),
			),
		),
		SetPacketBody(b),
	)

	// Marshal the entire packet to bytes
	packetBytes, err := packet.MarshalBinary()
	assert.NoError(t, err)

	// Create mock connection with the packet data
	mockConn := &mockConnection{data: packetBytes}
	c := &crypter{
		secret: []byte("test-secret"),
		Conn:   mockConn,
		Reader: bufio.NewReader(mockConn),
		tls:    true,
	}

	// Read the packet - this should trigger the unset flag reply mechanism
	readPacket, err := c.read()
	assert.Error(t, err)
	assert.Nil(t, readPacket)

	// Verify that an error response was written to the connection
	// The mockConnection should now have the error response in its data
	assert.Greater(t, len(mockConn.data), 0, "Expected error response to be written to connection")

	// Verify that the crypterReadFlagError counter was incremented
	counterAfter := testutil.ToFloat64(crypterReadFlagError)
	assert.Equal(t, counterBefore+1, counterAfter, "Expected crypterReadFlagError counter to be incremented")
}

// TestCrypterReadNonTLSEncrypted tests the read method with TLS disabled and encrypted packet
func TestCrypterReadNonTLSEncrypted(t *testing.T) {
	// Use the pre-existing encrypted test data
	encryptedBytes := getEncryptedBytes()

	// Create mock connection with encrypted packet data
	mockConn := &mockConnection{data: encryptedBytes}
	c := &crypter{
		secret: []byte("fooman"), // Use the matching secret for test data
		Conn:   mockConn,
		Reader: bufio.NewReader(mockConn),
		tls:    false,
	}

	// Read the packet
	readPacket, err := c.read()
	assert.NoError(t, err)
	assert.NotNil(t, readPacket)

	// Verify the packet was decrypted correctly
	assert.Equal(t, Authenticate, readPacket.Header.Type)
	assert.False(t, readPacket.Header.Flags.Has(UnencryptedFlag))
	assert.Equal(t, SessionID(12345), readPacket.Header.SessionID)

	// Verify the body was decrypted and can be unmarshaled correctly
	var readBody AuthenStart
	err = Unmarshal(readPacket.Body, &readBody)
	assert.NoError(t, err)
	assert.Equal(t, AuthenUser("admin"), readBody.User)
	assert.Equal(t, AuthenPort("command-api"), readBody.Port)
}

// TestCrypterReadNonTLSBadSecret tests the read method with TLS disabled and bad secret
func TestCrypterReadNonTLSBadSecret(t *testing.T) {
	// Use the pre-existing encrypted test data
	encryptedBytes := getEncryptedBytes()

	// Create mock connection with encrypted packet data
	mockConn := &mockConnection{data: encryptedBytes}
	c := &crypter{
		secret: []byte("bad-secret"), // Use wrong secret to trigger bad secret detection
		Conn:   mockConn,
		Reader: bufio.NewReader(mockConn),
		tls:    false,
	}

	// Read the packet - this should trigger bad secret detection
	readPacket, err := c.read()
	assert.Error(t, err)
	assert.Nil(t, readPacket)
	assert.Contains(t, err.Error(), "bad secret detected")

	// Verify that an error response was written to the connection
	assert.Greater(t, len(mockConn.data), 0, "Expected bad secret response to be written to connection")
}

// TestCrypterReadNonTLSUnencrypted tests the read method with TLS disabled and unencrypted packet
func TestCrypterReadNonTLSUnencrypted(t *testing.T) {
	// Create a valid TACACS+ packet with UnencryptedFlag set (for non-TLS)
	body := NewAuthenStart(
		SetAuthenStartAction(AuthenActionLogin),
		SetAuthenStartPrivLvl(PrivLvlUser),
		SetAuthenStartType(AuthenTypeASCII),
		SetAuthenStartService(AuthenServiceLogin),
		SetAuthenStartUser("admin"),
		SetAuthenStartPort("command-api"),
		SetAuthenStartRemAddr("127.0.0.1"),
	)
	b, _ := body.MarshalBinary()

	packet := NewPacket(
		SetPacketHeader(
			NewHeader(
				SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
				SetHeaderType(Authenticate),
				SetHeaderFlag(UnencryptedFlag), // Packet is unencrypted
				SetHeaderSessionID(12345),
			),
		),
		SetPacketBody(b),
	)

	// Marshal the entire packet to bytes
	packetBytes, err := packet.MarshalBinary()
	assert.NoError(t, err)

	// Create mock connection with the packet data
	mockConn := &mockConnection{data: packetBytes}
	c := &crypter{
		secret: []byte("test-secret"),
		Conn:   mockConn,
		Reader: bufio.NewReader(mockConn),
		tls:    false,
	}

	// Read the packet
	readPacket, err := c.read()
	assert.NoError(t, err)
	assert.NotNil(t, readPacket)

	// Verify the packet was read correctly (no decryption needed)
	assert.Equal(t, Authenticate, readPacket.Header.Type)
	assert.True(t, readPacket.Header.Flags.Has(UnencryptedFlag))
	assert.Equal(t, SessionID(12345), readPacket.Header.SessionID)

	// Verify the body can be unmarshaled correctly
	var readBody AuthenStart
	err = Unmarshal(readPacket.Body, &readBody)
	assert.NoError(t, err)
	assert.Equal(t, AuthenUser("admin"), readBody.User)
}

// TestCrypterReadProxyHeader tests the read method with proxy header enabled
func TestCrypterReadProxyHeader(t *testing.T) {
	// Create a valid TACACS+ packet
	body := NewAuthenStart(
		SetAuthenStartAction(AuthenActionLogin),
		SetAuthenStartPrivLvl(PrivLvlUser),
		SetAuthenStartType(AuthenTypeASCII),
		SetAuthenStartService(AuthenServiceLogin),
		SetAuthenStartUser("admin"),
		SetAuthenStartPort("command-api"),
		SetAuthenStartRemAddr("127.0.0.1"),
	)
	b, _ := body.MarshalBinary()

	packet := NewPacket(
		SetPacketHeader(
			NewHeader(
				SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
				SetHeaderType(Authenticate),
				SetHeaderFlag(UnencryptedFlag),
				SetHeaderSessionID(12345),
			),
		),
		SetPacketBody(b),
	)

	// Marshal the entire packet to bytes
	packetBytes, err := packet.MarshalBinary()
	assert.NoError(t, err)

	// Prepend a proxy header (null-terminated string)
	proxyHeader := "PROXY TCP4 192.168.1.1 192.168.1.2 12345 49\000"
	dataWithProxy := append([]byte(proxyHeader), packetBytes...)

	// Create mock connection with proxy header + packet data
	mockConn := &mockConnection{data: dataWithProxy}
	c := &crypter{
		secret: []byte("test-secret"),
		Conn:   mockConn,
		Reader: bufio.NewReader(mockConn),
		proxy:  true, // Enable proxy header processing
		tls:    true,
	}

	// Read the packet
	readPacket, err := c.read()
	assert.NoError(t, err)
	assert.NotNil(t, readPacket)

	// Verify the packet was read correctly after stripping proxy header
	assert.Equal(t, Authenticate, readPacket.Header.Type)
	assert.True(t, readPacket.Header.Flags.Has(UnencryptedFlag))
	assert.Equal(t, SessionID(12345), readPacket.Header.SessionID)
}

// TestCrypterReadInvalidPacketSize tests the read method with packet exceeding max body length
func TestCrypterReadInvalidPacketSize(t *testing.T) {
	// Create a valid header first
	header := NewHeader(
		SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
		SetHeaderType(Authenticate),
		SetHeaderSessionID(12345),
	)
	header.Length = 100 // Set to a valid length initially

	headerBytes, err := header.MarshalBinary()
	assert.NoError(t, err)

	// Now manually modify the length field in the raw bytes to exceed MaxBodyLength
	// The length field is at bytes 8-11 (big endian uint32)
	binary.BigEndian.PutUint32(headerBytes[8:12], MaxBodyLength+1)

	// Create mock connection with the modified header
	mockConn := &mockConnection{data: headerBytes}
	c := &crypter{
		secret: []byte("test-secret"),
		Conn:   mockConn,
		Reader: bufio.NewReader(mockConn),
		tls:    false,
	}

	// Read the packet - should fail due to exceeding max length
	readPacket, err := c.read()
	assert.Error(t, err)
	assert.Nil(t, readPacket)
	assert.Contains(t, err.Error(), "max header length exceeded")
}

// TestCrypterReadTLSReturnsCorrectPacket tests that TLS read returns the unmodified packet
func TestCrypterReadTLSReturnsCorrectPacket(t *testing.T) {
	// Create expected packet data
	body := NewAuthenStart(
		SetAuthenStartAction(AuthenActionLogin),
		SetAuthenStartPrivLvl(PrivLvlUser),
		SetAuthenStartType(AuthenTypeASCII),
		SetAuthenStartService(AuthenServiceLogin),
		SetAuthenStartUser("testuser"),
		SetAuthenStartPort("tty1"),
		SetAuthenStartRemAddr("10.0.0.1"),
	)
	b, _ := body.MarshalBinary()

	packet := NewPacket(
		SetPacketHeader(
			NewHeader(
				SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
				SetHeaderType(Authenticate),
				SetHeaderFlag(UnencryptedFlag),
				SetHeaderSessionID(54321),
				SetHeaderSeqNo(2),
			),
		),
		SetPacketBody(b),
	)

	// Marshal packet to bytes
	data, err := packet.MarshalBinary()
	assert.NoError(t, err)

	// Create mock connection
	mockConn := &mockConnection{data: data}
	c := &crypter{
		secret: []byte("test-secret"),
		Conn:   mockConn,
		Reader: bufio.NewReader(mockConn),
		tls:    true,
	}

	// Read packet
	readPacket, err := c.read()
	assert.NoError(t, err)
	assert.NotNil(t, readPacket)

	// Verify packet is returned unmodified (since TLS skips obfuscation)
	assert.Equal(t, packet.Header.Type, readPacket.Header.Type)
	assert.Equal(t, packet.Header.SessionID, readPacket.Header.SessionID)
	assert.Equal(t, packet.Header.SeqNo, readPacket.Header.SeqNo)
	assert.True(t, readPacket.Header.Flags.Has(UnencryptedFlag))

	// Verify body content
	var readBody AuthenStart
	err = Unmarshal(readPacket.Body, &readBody)
	assert.NoError(t, err)
	assert.Equal(t, AuthenUser("testuser"), readBody.User)
	assert.Equal(t, AuthenPort("tty1"), readBody.Port)
	assert.Equal(t, AuthenRemAddr("10.0.0.1"), readBody.RemAddr)
}

// TestDetectBadSecretWithUnencryptedFlag tests that detectBadSecret returns nil for unencrypted packets
func TestDetectBadSecretWithUnencryptedFlag(t *testing.T) {
	c := &crypter{}

	packet := &Packet{
		Header: NewHeader(
			SetHeaderType(Authenticate),
			SetHeaderFlag(UnencryptedFlag),
		),
		Body: []byte("test body"),
	}

	reply, err := c.detectBadSecret(packet)
	assert.NoError(t, err)
	assert.Nil(t, reply)
}
