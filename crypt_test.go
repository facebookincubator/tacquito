/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

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
