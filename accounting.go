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
// tacplus accounting
// https://datatracker.ietf.org/doc/html/rfc8907#section-7
//

// AcctRequestLen minumum length of this packet type
const AcctRequestLen = 0x9

// AcctRequestOption is used to inject options when creating new AcctRequest types
type AcctRequestOption func(*AcctRequest)

// SetAcctRequestFlag sets the AcctRequestFlag.
func SetAcctRequestFlag(v AcctRequestFlag) AcctRequestOption {
	return func(a *AcctRequest) {
		a.Flags = v
	}
}

// SetAcctRequestMethod sets the AuthenMethod.
func SetAcctRequestMethod(v AuthenMethod) AcctRequestOption {
	return func(a *AcctRequest) {
		a.Method = v
	}
}

// SetAcctRequestPrivLvl sets the PrivLvl.
func SetAcctRequestPrivLvl(v PrivLvl) AcctRequestOption {
	return func(a *AcctRequest) {
		a.PrivLvl = v
	}
}

// SetAcctRequestType sets the AuthenType.
func SetAcctRequestType(v AuthenType) AcctRequestOption {
	return func(a *AcctRequest) {
		a.Type = v
	}
}

// SetAcctRequestService sets the AuthenService.
func SetAcctRequestService(v AuthenService) AcctRequestOption {
	return func(a *AcctRequest) {
		a.Service = v
	}
}

// SetAcctRequestUser sets the AuthenUser.
func SetAcctRequestUser(v AuthenUser) AcctRequestOption {
	return func(a *AcctRequest) {
		a.User = v
	}
}

// SetAcctRequestPort sets the AuthenPort.
func SetAcctRequestPort(v AuthenPort) AcctRequestOption {
	return func(a *AcctRequest) {
		a.Port = v
	}
}

// SetAcctRequestRemAddr sets the AuthenRemAddr.
func SetAcctRequestRemAddr(v AuthenRemAddr) AcctRequestOption {
	return func(a *AcctRequest) {
		a.RemAddr = v
	}
}

// SetAcctRequestArgs sets the Args.
func SetAcctRequestArgs(v Args) AcctRequestOption {
	return func(a *AcctRequest) {
		a.Args = v
	}
}

// NewAcctRequest will create a new AcctRequest based on the provided options
func NewAcctRequest(opts ...AcctRequestOption) *AcctRequest {
	a := &AcctRequest{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// AcctRequest https://datatracker.ietf.org/doc/html/rfc8907#section-7.1
type AcctRequest struct {
	Flags   AcctRequestFlag
	Method  AuthenMethod
	PrivLvl PrivLvl
	Type    AuthenType
	Service AuthenService
	User    AuthenUser
	Port    AuthenPort
	RemAddr AuthenRemAddr
	Args    Args
}

// NewAccountingRequestFromBytes creates AcctRequest for tacacs decrypted bytes
func NewAccountingRequestFromBytes(data []byte) (*AcctRequest, error) {
	t := &AcctRequest{}
	return t, t.UnmarshalBinary(data)
}

// Validate all fields on this type
func (a *AcctRequest) Validate() error {
	// validate
	for _, t := range []Field{a.Method, a.PrivLvl, a.Type, a.Service, a.User, a.Port, a.RemAddr, a.Flags} {
		if err := t.Validate(nil); err != nil {
			return err
		}
	}
	for _, t := range a.Args {
		if err := AcctArg(t).Validate(nil); err != nil {
			return err
		}
	}
	return nil
}

// MarshalBinary marshals AccountingRequest to tacacs bytes
func (a *AcctRequest) MarshalBinary() ([]byte, error) {
	// validate
	if err := a.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, AcctRequestLen)
	buf = append(buf, uint8(a.Flags))
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

// UnmarshalBinary unmarshals decrypted tacacs bytes to AccountingRequest
func (a *AcctRequest) UnmarshalBinary(data []byte) error {
	if len(data) < AcctRequestLen {
		return fmt.Errorf("acctRequest size [%v] is too small for the minimum size [%v]", len(data), AcctRequestLen)
	}
	a.Flags = AcctRequestFlag(data[0])
	a.Method = AuthenMethod(data[1])
	a.PrivLvl = PrivLvl(data[2])
	a.Type = AuthenType(data[3])
	a.Service = AuthenService(data[4])

	userLen := int(data[5])
	portLen := int(data[6])
	remAddrLen := int(data[7])
	argCnt := int(data[8])

	buf := readBuffer(data[9:])

	var totalArgLen int
	argLens := make([]int, 0, argCnt)
	for i := 0; i < argCnt; i++ {
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
		return NewBadSecretErr("bad secret detected acctrequest")
	}
	// validate
	if err := a.Validate(); err != nil {
		return err
	}
	return nil
}

// Len will return the unmarshalled size of the component types
func (a AcctRequest) Len() int {
	sum := a.User.Len()
	sum += a.Port.Len()
	sum += a.RemAddr.Len()
	for _, arg := range a.Args {
		sum += arg.Len()
	}
	return sum
}

// Fields returns fields from this packet compatible with a structured logger
func (a AcctRequest) Fields() map[string]string {
	return map[string]string{
		"packet-type": "AcctRequest",
		"flags":       a.Flags.String(),
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

// AcctReplyLen minumum length of this packet type
const AcctReplyLen = 0x5

// AcctReplyOption is used to inject options when creating new AcctRequest types
type AcctReplyOption func(*AcctReply)

// SetAcctReplyStatus sets the AcctReplyStatus.
func SetAcctReplyStatus(v AcctReplyStatus) AcctReplyOption {
	return func(a *AcctReply) {
		a.Status = v
	}
}

// SetAcctReplyServerMsg sets the AcctServerMsg.
func SetAcctReplyServerMsg(v string) AcctReplyOption {
	return func(a *AcctReply) {
		a.ServerMsg = AcctServerMsg(v)
	}
}

// SetAcctReplyData sets the AcctData.
func SetAcctReplyData(v AcctData) AcctReplyOption {
	return func(a *AcctReply) {
		a.Data = v
	}
}

// NewAcctReply will create a new AcctReply based on the provided options
func NewAcctReply(opts ...AcctReplyOption) *AcctReply {
	a := &AcctReply{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// AcctReply https://datatracker.ietf.org/doc/html/rfc8907#section-7.2
type AcctReply struct {
	Status    AcctReplyStatus
	ServerMsg AcctServerMsg
	Data      AcctData
}

// NewAccountingReplyFromBytes creates AcctReply from decrypted tacacs bytes
func NewAccountingReplyFromBytes(data []byte) (*AcctReply, error) {
	t := &AcctReply{}
	return t, t.UnmarshalBinary(data)
}

// Validate all fields on this type
func (a *AcctReply) Validate() error {
	// validate
	for _, t := range []Field{a.Status, a.ServerMsg, a.Data} {
		if err := t.Validate(nil); err != nil {
			return err
		}
	}
	return nil
}

// MarshalBinary marshals AccountingReply to tacacs bytes
func (a *AcctReply) MarshalBinary() ([]byte, error) {
	// validate
	if err := a.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, AcctReplyLen)
	buf = appendUint16(buf, a.ServerMsg.Len())
	buf = appendUint16(buf, a.Data.Len())
	buf = append(buf, uint8(a.Status))
	buf = append(buf, a.ServerMsg...)
	buf = append(buf, a.Data...)

	return buf, nil
}

// UnmarshalBinary unmarshals decrypted tacacs bytes to AcctReply
func (a *AcctReply) UnmarshalBinary(data []byte) error {
	if len(data) < AcctReplyLen {
		return fmt.Errorf("acctReply size [%v] is too small for the minimum size [%v]", len(data), AcctReplyLen)
	}
	buf := readBuffer(data)
	serverMsgLen := buf.uint16()
	dataLen := buf.uint16()
	a.Status = AcctReplyStatus(buf.byte())

	a.ServerMsg = AcctServerMsg(buf.string(serverMsgLen))
	a.Data = AcctData(buf.string(dataLen))

	// detect secret mismatch
	if a.Len() != serverMsgLen+dataLen {
		return NewBadSecretErr("bad secret detected acctreply")
	}
	// validate
	if err := a.Validate(); err != nil {
		return err
	}
	return nil
}

// Len will return the unmarshalled size of the component types
func (a AcctReply) Len() int {
	sum := a.ServerMsg.Len()
	sum += a.Data.Len()
	return sum
}

// Fields returns fields from this packet compatible with a structured logger
func (a AcctReply) Fields() map[string]string {
	return map[string]string{
		"packet-type": "AcctReply",
		"status":      a.Status.String(),
		"server-msg":  a.ServerMsg.String(),
		"data":        a.Data.String(),
	}
}
