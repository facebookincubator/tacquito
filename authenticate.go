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
// tacplus authenticate message
// https://datatracker.ietf.org/doc/html/rfc8907#section-5
//

// AuthenStartLen minumum length of this packet type
const AuthenStartLen = 0x08

// AuthenStartOption is used to inject options when creating new AuthenStart types
type AuthenStartOption func(*AuthenStart)

// SetAuthenStartAction sets indicated authentication action
func SetAuthenStartAction(v AuthenAction) AuthenStartOption {
	return func(a *AuthenStart) {
		a.Action = v
	}
}

// SetAuthenStartPrivLvl sets the indicated authentication priv level
func SetAuthenStartPrivLvl(v PrivLvl) AuthenStartOption {
	return func(a *AuthenStart) {
		a.PrivLvl = v
	}
}

// SetAuthenStartType sets the indicated authentication type
func SetAuthenStartType(v AuthenType) AuthenStartOption {
	return func(a *AuthenStart) {
		a.Type = v
	}
}

// SetAuthenStartService sets the indicated authentication service
func SetAuthenStartService(v AuthenService) AuthenStartOption {
	return func(a *AuthenStart) {
		a.Service = v
	}
}

// SetAuthenStartUser sets the indicated user
func SetAuthenStartUser(v AuthenUser) AuthenStartOption {
	return func(a *AuthenStart) {
		a.User = v
	}
}

// SetAuthenStartPort sets the calling port
func SetAuthenStartPort(v AuthenPort) AuthenStartOption {
	return func(a *AuthenStart) {
		a.Port = v
	}
}

// SetAuthenStartRemAddr sets the remote address
func SetAuthenStartRemAddr(v AuthenRemAddr) AuthenStartOption {
	return func(a *AuthenStart) {
		a.RemAddr = v
	}
}

// SetAuthenStartData sets the authentication data
func SetAuthenStartData(v AuthenData) AuthenStartOption {
	return func(a *AuthenStart) {
		a.Data = v
	}
}

// NewAuthenStart will create a new AuthenStart based on the provided options
func NewAuthenStart(opts ...AuthenStartOption) *AuthenStart {
	a := &AuthenStart{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// AuthenStart https://datatracker.ietf.org/doc/html/rfc8907#section-5.1
type AuthenStart struct {
	Action  AuthenAction
	PrivLvl PrivLvl
	Type    AuthenType
	Service AuthenService
	User    AuthenUser
	Port    AuthenPort
	RemAddr AuthenRemAddr
	Data    AuthenData
}

// Validate all fields on this type
func (a *AuthenStart) Validate() error {
	// validate
	if a.Type == AuthenTypeNotSet {
		return fmt.Errorf("bad value for AuthenType; AuthenTypeNotSet not allowed for AuthenStart packets")
	}
	for _, t := range []Field{a.Action, a.PrivLvl, a.Type, a.Service, a.User, a.Port, a.RemAddr, a.Data} {
		if err := t.Validate(a.Type); err != nil {
			return err
		}
	}
	return nil
}

// MarshalBinary encodes AuthenStart to tacacs bytes
func (a *AuthenStart) MarshalBinary() ([]byte, error) {
	// validate
	if err := a.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, AuthenStartLen)
	buf = append(buf, uint8(a.Action))
	buf = append(buf, uint8(a.PrivLvl))
	buf = append(buf, uint8(a.Type))
	buf = append(buf, uint8(a.Service))

	buf = append(buf, uint8(a.User.Len()))
	buf = append(buf, uint8(a.Port.Len()))
	buf = append(buf, uint8(a.RemAddr.Len()))
	buf = append(buf, uint8(a.Data.Len()))

	buf = append(buf, a.User...)
	buf = append(buf, a.Port...)
	buf = append(buf, a.RemAddr...)
	buf = append(buf, a.Data...)

	return buf, nil
}

// UnmarshalBinary decodes decrypted tacacs bytes to AuthenStart
func (a *AuthenStart) UnmarshalBinary(data []byte) error {
	if len(data) < AuthenStartLen {
		return fmt.Errorf("authenStart size [%v] is too small for the minimum size [%v]", len(data), AuthenStartLen)
	}
	a.Action = AuthenAction(data[0])
	a.PrivLvl = PrivLvl(data[1])
	a.Type = AuthenType(data[2])
	a.Service = AuthenService(data[3])

	buf := readBuffer(data[4:])
	userLen := buf.int()
	portLen := buf.int()
	remAddrLen := buf.int()
	dataLen := buf.int()

	a.User = AuthenUser(buf.string(userLen))
	a.Port = AuthenPort(buf.string(portLen))
	a.RemAddr = AuthenRemAddr(buf.string(remAddrLen))
	a.Data = AuthenData(buf.string(dataLen))

	// detect secret mismatch
	if a.Len() != userLen+portLen+remAddrLen+dataLen {
		return NewBadSecretErr("bad secret detected authenstart")
	}
	// validate
	if err := a.Validate(); err != nil {
		return err
	}
	return nil
}

// Len will return the unmarshalled size of the component types
func (a AuthenStart) Len() int {
	sum := a.User.Len()
	sum += a.Port.Len()
	sum += a.RemAddr.Len()
	sum += a.Data.Len()
	return sum
}

// Fields returns fields from this packet compatible with a structured logger
func (a AuthenStart) Fields() map[string]string {
	return map[string]string{
		"packet-type": "AuthenStart",
		"action":      a.Action.String(),
		"priv-lvl":    a.PrivLvl.String(),
		"type":        a.Type.String(),
		"service":     a.Service.String(),
		"user":        a.User.String(),
		"port":        a.Port.String(),
		"rem-addr":    a.RemAddr.String(),
		"data":        a.Data.String(),
	}
}

// AuthenContinueLen minumum length of this packet type
const AuthenContinueLen = 0x05

// AuthenContinueOption is used to inject options when creating new AuthenContinue types
type AuthenContinueOption func(*AuthenContinue)

// SetAuthenContinueFlag sets AuthenContinueFlag
func SetAuthenContinueFlag(v AuthenContinueFlag) AuthenContinueOption {
	return func(a *AuthenContinue) {
		a.Flags = v
	}
}

// SetAuthenContinueUserMessage sets AuthenUserMessage
func SetAuthenContinueUserMessage(v AuthenUserMessage) AuthenContinueOption {
	return func(a *AuthenContinue) {
		a.UserMessage = v
	}
}

// SetAuthenContinueData sets AuthenData
func SetAuthenContinueData(v AuthenData) AuthenContinueOption {
	return func(a *AuthenContinue) {
		a.Data = v
	}
}

// NewAuthenContinue will create a new AuthenContinue based on the provided options
func NewAuthenContinue(opts ...AuthenContinueOption) *AuthenContinue {
	a := &AuthenContinue{}
	var f AuthenContinueFlag
	defaults := []AuthenContinueOption{
		SetAuthenContinueFlag(f),
	}
	opts = append(defaults, opts...)
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// AuthenContinue see https://datatracker.ietf.org/doc/html/rfc8907#section-5.3
type AuthenContinue struct {
	Flags       AuthenContinueFlag
	UserMessage AuthenUserMessage
	Data        AuthenData
}

// Validate all fields on this type
func (a *AuthenContinue) Validate() error {
	// validate
	for _, t := range []Field{a.UserMessage, a.Data} {
		if err := t.Validate(nil); err != nil {
			return err
		}
	}
	return nil
}

// MarshalBinary encodes AuthenContinue to tacacs bytes
func (a *AuthenContinue) MarshalBinary() ([]byte, error) {
	// validate
	if err := a.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, AuthenContinueLen)
	buf = appendUint16(buf, a.UserMessage.Len())
	buf = appendUint16(buf, a.Data.Len())
	buf = append(buf, uint8(a.Flags))

	buf = append(buf, a.UserMessage...)
	buf = append(buf, a.Data...)

	return buf, nil
}

// UnmarshalBinary decodes decrypted tacacs bytes to AuthenContinue
func (a *AuthenContinue) UnmarshalBinary(data []byte) error {
	if len(data) < AuthenContinueLen {
		return fmt.Errorf("authenContinue size [%v] is too small for the minimum size [%v]", len(data), AuthenContinueLen)
	}
	buf := readBuffer(data)
	userMessageLen := buf.uint16()
	dataLen := buf.uint16()
	a.Flags = AuthenContinueFlag(buf.byte())

	a.UserMessage = AuthenUserMessage(buf.string(userMessageLen))
	a.Data = AuthenData(buf.string(dataLen))

	// detect secret mismatch
	if a.Len() != userMessageLen+dataLen {
		return NewBadSecretErr("bad secret detected authencontinue")
	}
	// validate
	if err := a.Validate(); err != nil {
		return err
	}
	return nil
}

// Len will return the unmarshalled size of the component types
func (a AuthenContinue) Len() int {
	sum := a.UserMessage.Len()
	sum += a.Data.Len()
	return sum
}

// Fields returns fields from this packet compatible with a structured logger
func (a AuthenContinue) Fields() map[string]string {
	return map[string]string{
		"packet-type": "AuthenContinue",
		"flags":       a.Flags.String(),
		"user-msg":    a.UserMessage.String(),
		"data":        a.Data.String(),
	}
}

// AuthenReplyLen minumum length of this packet type
const AuthenReplyLen = 0x05

// AuthenReplyOption is used to inject options when creating new AuthenReply types
type AuthenReplyOption func(*AuthenReply)

// SetAuthenReplyStatus sets an AuthenStatus
func SetAuthenReplyStatus(v AuthenStatus) AuthenReplyOption {
	return func(a *AuthenReply) {
		a.Status = v
	}
}

// SetAuthenReplyFlag sets an AuthenReplyFlag
func SetAuthenReplyFlag(v AuthenReplyFlag) AuthenReplyOption {
	return func(a *AuthenReply) {
		a.Flags = v
	}
}

// SetAuthenReplyServerMsg sets an AuthenServerMsg
func SetAuthenReplyServerMsg(v string) AuthenReplyOption {
	return func(a *AuthenReply) {
		a.ServerMsg = AuthenServerMsg(v)
	}
}

// SetAuthenReplyData sets an AuthenData
func SetAuthenReplyData(v AuthenData) AuthenReplyOption {
	return func(a *AuthenReply) {
		a.Data = v
	}
}

// NewAuthenReply will create a new AuthenReply based on the provided options
func NewAuthenReply(opts ...AuthenReplyOption) *AuthenReply {
	a := &AuthenReply{}
	for _, opt := range opts {
		opt(a)
	}
	return a
}

// AuthenReply https://datatracker.ietf.org/doc/html/rfc8907#section-5.2
type AuthenReply struct {
	Status    AuthenStatus
	Flags     AuthenReplyFlag
	ServerMsg AuthenServerMsg
	Data      AuthenData
}

// Validate all fields on this type
func (a *AuthenReply) Validate() error {
	// validate
	for _, t := range []Field{a.Status} {
		if err := t.Validate(nil); err != nil {
			return err
		}
	}
	return nil
}

// MarshalBinary encodes AuthenReply to tacacs bytes
func (a *AuthenReply) MarshalBinary() ([]byte, error) {
	// validate
	if err := a.Validate(); err != nil {
		return nil, err
	}
	buf := make([]byte, 0, AuthenReplyLen)
	buf = append(buf, uint8(a.Status))
	buf = append(buf, uint8(a.Flags))

	buf = appendUint16(buf, a.ServerMsg.Len())
	buf = appendUint16(buf, a.Data.Len())
	buf = append(buf, a.ServerMsg...)
	buf = append(buf, a.Data...)

	return buf, nil
}

// UnmarshalBinary decodes decrypted tacacs bytes to AuthenReply
func (a *AuthenReply) UnmarshalBinary(data []byte) error {
	if len(data) < AuthenReplyLen {
		return fmt.Errorf("authenReply size [%v] is too small for the minimum size [%v]", len(data), AuthenReplyLen)
	}
	a.Status = AuthenStatus(data[0])
	a.Flags = AuthenReplyFlag(data[1])

	buf := readBuffer(data[2:])
	serverMsgLen := buf.uint16()
	dataLen := buf.uint16()

	a.ServerMsg = AuthenServerMsg(buf.string(serverMsgLen))
	a.Data = AuthenData(buf.string(dataLen))

	// detect secret mismatch
	if a.Len() != serverMsgLen+dataLen {
		return NewBadSecretErr("bad secret detected authenreply")
	}

	// validate
	if err := a.Validate(); err != nil {
		return err
	}
	return nil
}

// Len will return the unmarshalled size of the component types
func (a AuthenReply) Len() int {
	sum := a.ServerMsg.Len()
	sum += a.Data.Len()
	return sum
}

// Fields returns fields from this packet compatible with a structured logger
func (a AuthenReply) Fields() map[string]string {
	return map[string]string{
		"packet-type": "AuthenReply",
		"status":      a.Status.String(),
		"flags":       a.Flags.String(),
		"server-msg":  a.ServerMsg.String(),
		"data":        a.Data.String(),
	}
}
