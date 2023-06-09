/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"encoding/binary"
	"math/rand"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/assert"
)

var characters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

func stringOfLength(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = characters[rand.Intn(len(characters))]
	}
	return string(b)
}

// TestReadBuffer inspects various error conditions that could cause readBuffer to panic
// we don't want that in a server so lets make sure it doesn't panic, particulary index errors
func TestReadBuffer(t *testing.T) {
	// should not panic on empty data, or undersized data
	b := readBuffer([]byte{})
	assert.Equal(t, 0, b.int())

	b = readBuffer([]byte{})
	assert.Equal(t, uint8(0), b.byte())

	b = readBuffer([]byte{})
	assert.Equal(t, 0, b.uint16())

	b = readBuffer([]byte{})
	assert.Equal(t, "", b.string(6))

	// string should be the right len if we asked for too much
	b = readBuffer([]byte("asdfg"))
	assert.Equal(t, 5, len(b.string(6)))
}

func TestHeaderFlagBitSet(t *testing.T) {
	var f HeaderFlag
	f.Set(UnencryptedFlag)
	f.Set(SingleConnect)
	assert.Equal(t, HeaderFlag(5), f)
	assert.True(t, f.Has(UnencryptedFlag))
	assert.True(t, f.Has(SingleConnect))

	f.Clear(UnencryptedFlag)
	assert.Equal(t, HeaderFlag(4), f)

	f.Clear(SingleConnect)
	assert.Equal(t, HeaderFlag(0), f)

	assert.False(t, f.Has(UnencryptedFlag))
	assert.False(t, f.Has(SingleConnect))

	f.Set(SingleConnect)
	assert.True(t, f.Has(SingleConnect))
	f.Toggle(SingleConnect)
	assert.False(t, f.Has(SingleConnect))
}

func TestHeaderMarshalUnmarshal(t *testing.T) {
	var f HeaderFlag
	f.Set(SingleConnect)
	v := NewHeader(
		SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
		SetHeaderType(Authenticate),
		SetHeaderSeqNo(1),
		SetHeaderFlag(f),
		SetHeaderSessionID(12345),
	)

	buf, err := v.MarshalBinary()
	assert.NoError(t, err)
	t.Log(spew.Sdump(buf))

	decoded := &Header{}
	err = decoded.UnmarshalBinary(buf)
	assert.NoError(t, err)
	t.Log(spew.Sdump(decoded))
	assert.Equal(t, v, decoded)
}

func TestAuthenStartMarshalUnmarshal(t *testing.T) {
	v := NewAuthenStart(
		SetAuthenStartAction(AuthenActionLogin),
		SetAuthenStartPrivLvl(PrivLvlRoot),
		SetAuthenStartType(AuthenTypeASCII),
		SetAuthenStartService(AuthenServiceLogin),
		SetAuthenStartPort("4"),
		SetAuthenStartRemAddr("async"),
	)
	buf, err := v.MarshalBinary()
	assert.NoError(t, err)
	t.Log(spew.Sdump(buf))

	decoded := &AuthenStart{}
	err = decoded.UnmarshalBinary(buf)
	assert.NoError(t, err)
	t.Log(spew.Sdump(decoded))
	assert.Equal(t, v, decoded)
}

func TestAuthenReplyMarshalUnmarshal(t *testing.T) {
	v := NewAuthenReply(
		SetAuthenReplyStatus(AuthenStatusGetUser),
		SetAuthenReplyServerMsg("\nUser Access Verification\n\nUsername:"),
	)

	buf, err := v.MarshalBinary()
	assert.NoError(t, err)
	t.Log(spew.Sdump(buf))

	decoded := &AuthenReply{}
	err = decoded.UnmarshalBinary(buf)
	assert.NoError(t, err)
	t.Log(spew.Sdump(decoded))
	assert.Equal(t, v, decoded)
}

func TestAuthenContinueMarshalUnmarshal(t *testing.T) {
	v := NewAuthenContinue(
		SetAuthenContinueUserMessage("\nmore prompting"),
	)

	buf, err := v.MarshalBinary()
	assert.NoError(t, err)
	t.Log(spew.Sdump(buf))

	decoded := &AuthenContinue{}
	err = decoded.UnmarshalBinary(buf)
	assert.NoError(t, err)
	t.Log(spew.Sdump(decoded))
	assert.Equal(t, v, decoded)
}

func TestAuthorRequestMarshalUnmarshal(t *testing.T) {
	v := NewAuthorRequest(
		SetAuthorRequestMethod(AuthenMethodTacacsPlus),
		SetAuthorRequestPrivLvl(PrivLvlRoot),
		SetAuthorRequestType(AuthenTypeASCII),
		SetAuthorRequestService(AuthenServiceLogin),
		SetAuthorRequestPort("4"),
		SetAuthorRequestRemAddr("async"),
		SetAuthorRequestArgs(Args{Arg("show"), Arg("system"), Arg(stringOfLength(2)), Arg(stringOfLength(255))}),
	)
	buf, err := v.MarshalBinary()
	assert.Nil(t, err)
	t.Log(spew.Sdump(buf))

	decoded := &AuthorRequest{}
	err = decoded.UnmarshalBinary(buf)
	assert.NoError(t, err)
	t.Log(spew.Sdump(decoded))
	assert.Equal(t, v, decoded)

	// arg is too short < 2
	v = NewAuthorRequest(
		SetAuthorRequestMethod(AuthenMethodTacacsPlus),
		SetAuthorRequestPrivLvl(PrivLvlRoot),
		SetAuthorRequestType(AuthenTypeASCII),
		SetAuthorRequestService(AuthenServiceLogin),
		SetAuthorRequestPort("4"),
		SetAuthorRequestRemAddr("async"),
		SetAuthorRequestArgs(Args{Arg("a")}),
	)
	_, err = v.MarshalBinary()
	assert.Error(t, err)

	// arg is too long > 255
	v = NewAuthorRequest(
		SetAuthorRequestMethod(AuthenMethodTacacsPlus),
		SetAuthorRequestPrivLvl(PrivLvlRoot),
		SetAuthorRequestType(AuthenTypeASCII),
		SetAuthorRequestService(AuthenServiceLogin),
		SetAuthorRequestPort("4"),
		SetAuthorRequestRemAddr("async"),
		SetAuthorRequestArgs(Args{Arg(stringOfLength(256))}),
	)
	_, err = v.MarshalBinary()
	assert.Error(t, err)
}

func TestAuthorReplyMarshalUnmarshal(t *testing.T) {
	v := NewAuthorReply(
		SetAuthorReplyStatus(AuthorStatusPassAdd),
		SetAuthorReplyArgs("show", "system"),
		SetAuthorReplyServerMsg("i am a message from the server"),
		SetAuthorReplyData("some data"),
	)
	buf, err := v.MarshalBinary()
	assert.NoError(t, err)
	t.Log(spew.Sdump(buf))

	decoded := &AuthorReply{}
	err = decoded.UnmarshalBinary(buf)
	assert.NoError(t, err)
	t.Log(spew.Sdump(decoded))
	assert.Equal(t, v, decoded)
}

func TestAcctRequestMarshalUnmarshal(t *testing.T) {
	var f AcctRequestFlag
	f.Set(AcctFlagStart)
	v := NewAcctRequest(
		SetAcctRequestFlag(f),
		SetAcctRequestMethod(AuthenMethodTacacsPlus),
		SetAcctRequestPrivLvl(PrivLvlRoot),
		SetAcctRequestType(AuthenTypeASCII),
		SetAcctRequestService(AuthenServiceLogin),
		SetAcctRequestPort("4"),
		SetAcctRequestRemAddr("async"),
		SetAcctRequestArgs(Args{Arg("show"), Arg("system")}),
	)

	buf, err := v.MarshalBinary()
	assert.NoError(t, err)
	t.Log(spew.Sdump(buf))

	decoded := &AcctRequest{}
	err = decoded.UnmarshalBinary(buf)
	assert.NoError(t, err)
	t.Log(spew.Sdump(decoded))
	assert.Equal(t, v, decoded)

	// arg is 0 this should not err
	v = NewAcctRequest(
		SetAcctRequestFlag(f),
		SetAcctRequestMethod(AuthenMethodTacacsPlus),
		SetAcctRequestPrivLvl(PrivLvlRoot),
		SetAcctRequestType(AuthenTypeASCII),
		SetAcctRequestService(AuthenServiceLogin),
		SetAcctRequestPort("4"),
		SetAcctRequestRemAddr("async"),
		SetAcctRequestArgs(Args{Arg(stringOfLength(0))}),
	)
	_, err = v.MarshalBinary()
	assert.NoError(t, err)

	// arg is too long > 255 it should err
	v = NewAcctRequest(
		SetAcctRequestFlag(f),
		SetAcctRequestMethod(AuthenMethodTacacsPlus),
		SetAcctRequestPrivLvl(PrivLvlRoot),
		SetAcctRequestType(AuthenTypeASCII),
		SetAcctRequestService(AuthenServiceLogin),
		SetAcctRequestPort("4"),
		SetAcctRequestRemAddr("async"),
		SetAcctRequestArgs(Args{Arg(stringOfLength(256))}),
	)
	_, err = v.MarshalBinary()
	assert.Error(t, err)
}

func TestAcctReplyMarshalUnmarshal(t *testing.T) {
	v := NewAcctReply(
		SetAcctReplyStatus(AcctReplyStatusSuccess),
		SetAcctReplyServerMsg("i am a message from the server"),
		SetAcctReplyData("random data"),
	)
	buf, err := v.MarshalBinary()
	assert.NoError(t, err)
	t.Log(spew.Sdump(buf))

	decoded := &AcctReply{}
	err = decoded.UnmarshalBinary(buf)
	assert.NoError(t, err)
	t.Log(spew.Sdump(decoded))
	assert.Equal(t, v, decoded)
}

func TestPacketMarshalUnmarshalTooLarge(t *testing.T) {
	var f HeaderFlag
	f.Set(SingleConnect)
	h := NewHeader(
		SetHeaderVersion(Version{MajorVersion: MajorVersion, MinorVersion: MinorVersionOne}),
		SetHeaderType(Authenticate),
		SetHeaderSeqNo(1),
		SetHeaderFlag(f),
		SetHeaderSessionID(12345),
		SetHeaderLen(int(MaxHeaderLength)),
	)
	p := NewPacket(SetPacketHeader(h), SetPacketBody(make([]byte, MaxBodyLength)))
	buf, err := p.MarshalBinary()
	assert.NoError(t, err)

	// make it too big
	binary.BigEndian.PutUint32(buf[8:], MaxBodyLength+1)
	p.Header.Length++

	// won't marshal
	_, err = p.MarshalBinary()
	assert.Error(t, err)

	// won't unmarhsal
	err = p.UnmarshalBinary(buf)
	assert.Error(t, err)
}
