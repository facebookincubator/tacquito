/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"fmt"
)

//
// tacplus authorization message
// https://datatracker.ietf.org/doc/html/rfc8907#section-6
//

// AuthorRequestLen minumum length of this packet type
const AuthorRequestLen = 0x8

// AuthorRequestOption is used to inject options when creating new AuthorRequest types
type AuthorRequestOption func(*AuthorRequest)

// SetAuthorRequestMethod sets the AuthenMethod.
func SetAuthorRequestMethod(v AuthenMethod) AuthorRequestOption {
	return func(a *AuthorRequest) {
		a.Method = v
	}
}

// SetAuthorRequestPrivLvl sets the PrivLvl
func SetAuthorRequestPrivLvl(v PrivLvl) AuthorRequestOption {
	return func(a *AuthorRequest) {
		a.PrivLvl = v
	}
}

// SetAuthorRequestType sets the AuthenType.
func SetAuthorRequestType(v AuthenType) AuthorRequestOption {
	return func(a *AuthorRequest) {
		a.Type = v
	}
}

// SetAuthorRequestService sets the AuthenService.
func SetAuthorRequestService(v AuthenService) AuthorRequestOption {
	return func(a *AuthorRequest) {
		a.Service = v
	}
}

// SetAuthorRequestUser sets the AuthenUser.
func SetAuthorRequestUser(v AuthenUser) AuthorRequestOption {
	return func(a *AuthorRequest) {
		a.User = v
	}
}

// SetAuthorRequestPort sets the AuthenPort.
func SetAuthorRequestPort(v AuthenPort) AuthorRequestOption {
	return func(a *AuthorRequest) {
		a.Port = v
	}
}

// SetAuthorRequestRemAddr sets the AuthenRemAddr.
func SetAuthorRequestRemAddr(v AuthenRemAddr) AuthorRequestOption {
	return func(a *AuthorRequest) {
		a.RemAddr = v
	}
}

// SetAuthorRequestArgs sets the Args.
func SetAuthorRequestArgs(v Args) AuthorRequestOption {
	return func(a *AuthorRequest) {
		a.Args = v
	}
}

// NewAuthorRequest will create a new AuthorRequest based on the provided options
func NewAuthorRequest(opts ...AuthorRequestOption) *AuthorRequest {
	a := &AuthorRequest{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// AuthorRequest https://datatracker.ietf.org/doc/html/rfc8907#section-6.1
type AuthorRequest struct {
	Method  AuthenMethod
	PrivLvl PrivLvl
	Type    AuthenType
	Service AuthenService
	User    AuthenUser
	Port    AuthenPort
	RemAddr AuthenRemAddr
	Args    Args
}

// Validate all fields on this type
func (a *AuthorRequest) Validate() error {
	// validate
	for _, t := range []Field{a.Method, a.PrivLvl, a.Type, a.Service, a.User, a.Port, a.RemAddr} {
		if err := t.Validate(a.Type); err != nil {
			return err
		}
	}
	for _, t := range a.Args {
		if err := t.Validate(nil); err != nil {
			return err
		}
	}
	return nil
}

// MarshalBinary encodes AuthroRequest into tacacs bytes
func (a *AuthorRequest) MarshalBinary() ([]byte, error) {
	// validate we have good data before encoding
	if err := a.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, AuthorRequestLen+len(a.Args))
	buf = append(buf, uint8(a.Method))
	buf = append(buf, uint8(a.PrivLvl))
	buf = append(buf, uint8(a.Type))
	buf = append(buf, uint8(a.Service))

	buf = append(buf, uint8(a.User.Len()))
	buf = append(buf, uint8(a.Port.Len()))
	buf = append(buf, uint8(a.RemAddr.Len()))
	buf = append(buf, uint8(len(a.Args)))

	for _, arg := range a.Args {
		buf = append(buf, uint8(arg.Len()))
	}

	buf = append(buf, a.User...)
	buf = append(buf, a.Port...)
	buf = append(buf, a.RemAddr...)

	for _, arg := range a.Args {
		buf = append(buf, arg...)
	}

	return buf, nil
}

// UnmarshalBinary decodes decrypted tacacs bytes into AuthorRequest
func (a *AuthorRequest) UnmarshalBinary(data []byte) error {
	if len(data) < AuthorRequestLen {
		return fmt.Errorf("authorRequest size [%v] is too small for the minimum size [%v]", len(data), AuthorRequestLen)
	}
	a.Method = AuthenMethod(data[0])
	a.PrivLvl = PrivLvl(data[1])
	a.Type = AuthenType(data[2])
	a.Service = AuthenService(data[3])

	buf := readBuffer(data[4:])
	userLen := buf.int()
	portLen := buf.int()
	remAddrLen := buf.int()
	argCnt := buf.int()

	var totalArgLen int
	argLens := make([]int, 0, argCnt)
	for range argCnt {
		aLen := buf.int()
		totalArgLen += aLen
		argLens = append(argLens, aLen)
	}

	a.User = AuthenUser(buf.string(userLen))
	a.Port = AuthenPort(buf.string(portLen))
	a.RemAddr = AuthenRemAddr(buf.string(remAddrLen))

	a.Args = make(Args, 0, argCnt)
	for _, n := range argLens {
		a.Args = append(a.Args, Arg(buf.string(n)))
	}

	// detect secret mismatch
	if a.Len() != userLen+portLen+remAddrLen+totalArgLen {
		return NewBadSecretErr("bad secret detected authorrequest")
	}
	// validate
	if err := a.Validate(); err != nil {
		return err
	}
	return nil
}

// Len will return the unmarshalled size of the component types
func (a AuthorRequest) Len() int {
	sum := a.User.Len()
	sum += a.Port.Len()
	sum += a.RemAddr.Len()
	for _, arg := range a.Args {
		sum += arg.Len()
	}
	return sum
}

// Fields returns fields from this packet compatible with a structured logger
func (a AuthorRequest) Fields() map[string]string {
	return map[string]string{
		"packet-type": "AuthorRequest",
		"method":      a.Method.String(),
		"priv-lvl":    a.PrivLvl.String(),
		"type":        a.Type.String(),
		"service":     a.Service.String(),
		"user":        a.User.String(),
		"port":        a.Port.String(),
		"rem-addr":    a.RemAddr.String(),
		"args":        a.Args.String(),
	}
}

// AuthorReplyLen minumum length of this packet type
const AuthorReplyLen = 0x6

// AuthorReplyOption is used to inject options when creating new AuthorRequest types
type AuthorReplyOption func(*AuthorReply)

// SetAuthorReplyStatus sets the AuthorStatus.
func SetAuthorReplyStatus(v AuthorStatus) AuthorReplyOption {
	return func(a *AuthorReply) {
		a.Status = v
	}
}

// SetAuthorReplyArgs sets the Args.
func SetAuthorReplyArgs(args ...string) AuthorReplyOption {
	return func(a *AuthorReply) {
		v := make(Args, 0, len(args))
		for _, arg := range args {
			v = append(v, Arg(arg))
		}
		a.Args = v
	}
}

// SetAuthorReplyServerMsg sets the AuthorServerMsg.
func SetAuthorReplyServerMsg(v string) AuthorReplyOption {
	return func(a *AuthorReply) {
		a.ServerMsg = AuthorServerMsg(v)
	}
}

// SetAuthorReplyData sets the AuthorData.
func SetAuthorReplyData(v AuthorData) AuthorReplyOption {
	return func(a *AuthorReply) {
		a.Data = v
	}
}

// NewAuthorReply will create a new AuthorReply based on the provided options
func NewAuthorReply(opts ...AuthorReplyOption) *AuthorReply {
	a := &AuthorReply{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// AuthorReply https://datatracker.ietf.org/doc/html/rfc8907#section-6.2
type AuthorReply struct {
	Status    AuthorStatus
	Args      Args
	ServerMsg AuthorServerMsg
	Data      AuthorData
}

// NewAuthorReplyFromBytes decodes decrypted tacacs bytes into AuthorReply
func NewAuthorReplyFromBytes(data []byte) (*AuthorReply, error) {
	t := &AuthorReply{}
	return t, t.UnmarshalBinary(data)
}

// Validate all fields on this type
func (a *AuthorReply) Validate() error {
	// validate
	for _, t := range []Field{a.Status, a.ServerMsg, a.Data} {
		if err := t.Validate(nil); err != nil {
			return err
		}
	}
	for _, t := range a.Args {
		if err := t.Validate(nil); err != nil {
			return err
		}
	}
	return nil
}

// MarshalBinary encodes AuthorReply into tacacs bytes
func (a *AuthorReply) MarshalBinary() ([]byte, error) {
	// validate
	if err := a.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, AuthorReplyLen)
	buf = append(buf, uint8(a.Status))
	buf = append(buf, uint8(len(a.Args)))
	buf = appendUint16(buf, a.ServerMsg.Len())
	buf = appendUint16(buf, a.Data.Len())

	for _, arg := range a.Args {
		buf = append(buf, uint8(arg.Len()))
	}

	buf = append(buf, a.ServerMsg...)
	buf = append(buf, a.Data...)

	for _, arg := range a.Args {
		buf = append(buf, arg...)
	}

	return buf, nil
}

// UnmarshalBinary decodes decrypted tacacs bytes into AuthorReply
func (a *AuthorReply) UnmarshalBinary(data []byte) error {
	if len(data) < AuthorReplyLen {
		return fmt.Errorf("authorReply size [%v] is too small for the minimum size [%v]", len(data), AuthorReplyLen)
	}

	buf := readBuffer(data)

	a.Status = AuthorStatus(buf.byte())
	argCnt := buf.int()
	serverMsgLen := buf.uint16()
	dataLen := buf.uint16()

	var totalArgLen int
	argLens := make([]int, 0, argCnt)
	for range argCnt {
		aLen := buf.int()
		totalArgLen += aLen
		argLens = append(argLens, aLen)
	}

	a.ServerMsg = AuthorServerMsg(buf.string(serverMsgLen))
	a.Data = AuthorData(buf.string(dataLen))

	a.Args = make(Args, 0, argCnt)
	for _, n := range argLens {
		a.Args = append(a.Args, Arg(buf.string(n)))
	}
	// detect secret mismatch
	if a.Len() != serverMsgLen+dataLen+totalArgLen {
		return NewBadSecretErr("bad secret detected authorreply")
	}
	// validate
	if err := a.Validate(); err != nil {
		return err
	}
	return nil
}

// Len will return the unmarshalled size of the component types
func (a AuthorReply) Len() int {
	sum := a.ServerMsg.Len()
	sum += a.Data.Len()
	for _, arg := range a.Args {
		sum += arg.Len()
	}
	return sum
}

// Fields returns fields from this packet compatible with a structured logger
func (a AuthorReply) Fields() map[string]string {
	return map[string]string{
		"packet-type": "AuthorReply",
		"status":      a.Status.String(),
		"args":        a.Args.String(),
		"server-msg":  a.ServerMsg.String(),
		"data":        a.Data.String(),
	}
}
