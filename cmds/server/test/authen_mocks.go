/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package test

import (
	"fmt"

	tq "github.com/facebookincubator/tacquito"

	"github.com/davecgh/go-spew/spew"
)

// BuildASCIIStartPacket ..
func BuildASCIIStartPacket() *tq.Packet {
	return tq.NewPacket(
		tq.SetPacketHeader(
			tq.NewHeader(
				tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
				tq.SetHeaderType(tq.Authenticate),
				tq.SetHeaderRandomSessionID(),
			),
		),
		tq.SetPacketBodyUnsafe(
			tq.NewAuthenStart(
				tq.SetAuthenStartAction(tq.AuthenActionLogin),
				tq.SetAuthenStartPrivLvl(tq.PrivLvlUser),
				tq.SetAuthenStartType(tq.AuthenTypeASCII),
				tq.SetAuthenStartService(tq.AuthenServiceLogin),
				tq.SetAuthenStartPort("tty0"),
				tq.SetAuthenStartRemAddr("foo"),
			),
		),
	)
}

// ASCIILoginFullFlow ...
func ASCIILoginFullFlow() Test {
	startPacket := BuildASCIIStartPacket()
	return Test{
		Name:   "ascii login full flow",
		Secret: []byte("fooman"),
		Seq: []Sequence{
			{
				Packet: startPacket,
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetUser {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetUser")
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
							tq.SetHeaderSessionID(startPacket.Header.SessionID),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueUserMessage("mr_uses_group"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetPass {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetPass")
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
							tq.SetHeaderSessionID(startPacket.Header.SessionID),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueUserMessage("password"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusPass {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusPass")
					}
					return nil
				},
			},
		},
	}
}

// PapLoginFlow ...
func PapLoginFlow() Test {
	return Test{
		Name:   "pap login full flow",
		Secret: []byte("fooman"),
		Seq: []Sequence{
			{
				Packet: tq.NewPacket(
					tq.SetPacketHeader(
						tq.NewHeader(
							tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionOne}),
							tq.SetHeaderType(tq.Authenticate),
							tq.SetHeaderRandomSessionID(),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenStart(
							tq.SetAuthenStartType(tq.AuthenTypePAP),
							tq.SetAuthenStartAction(tq.AuthenActionLogin),
							tq.SetAuthenStartPrivLvl(tq.PrivLvl(15)),
							tq.SetAuthenStartPort("tty0"),
							tq.SetAuthenStartRemAddr("rem port"),
							tq.SetAuthenStartUser("mr_uses_group"),
							tq.SetAuthenStartData("password"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusPass {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusPass")
					}
					return nil
				},
			},
		},
	}
}

// ASCIILoginEnable ..
func ASCIILoginEnable() Test {
	startPacket := BuildASCIIStartPacket()
	return Test{
		Name:   "ascii enable full flow",
		Secret: []byte("fooman"),
		Seq: []Sequence{
			{
				Packet: startPacket,
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetUser {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetUser")
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
							tq.SetHeaderSessionID(startPacket.Header.SessionID),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueUserMessage("mr_uses_group"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetPass {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetPass")
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
							tq.SetHeaderSessionID(startPacket.Header.SessionID),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueUserMessage("password"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusPass {
						return fmt.Errorf("failed to match AuthenStatusPass")
					}
					return nil
				},
			},
		},
	}
}

// GetASCIILoginAbortTests ...
// https://datatracker.ietf.org/doc/html/rfc8907#section-5.4
func GetASCIILoginAbortTests() []Test {
	var authenContinueFlag tq.AuthenContinueFlag
	authenContinueFlag.Set(tq.AuthenContinueFlagAbort)
	startPacket := BuildASCIIStartPacket()
	onStart := Test{
		Name:   "test authen abort on first client packet",
		Secret: []byte("fooman"),
		Seq: []Sequence{
			{
				Packet: startPacket,
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetUser {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetUser")
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
							tq.SetHeaderSessionID(startPacket.Header.SessionID),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueFlag(authenContinueFlag),
							tq.SetAuthenContinueUserMessage("Continue inside"),
							tq.SetAuthenContinueData("foo"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusFail {
						spew.Dump(body)
						return fmt.Errorf("expecting a authenStatusFail because client sent an abort")
					}
					return nil
				},
			},
		},
	}
	startPacket = BuildASCIIStartPacket()
	onUser := Test{
		Name:   "test authen abort on user sending username",
		Secret: []byte("fooman"),
		Seq: []Sequence{
			{
				Packet: startPacket,
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetUser {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetUser")
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
							tq.SetHeaderSessionID(startPacket.Header.SessionID),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueUserMessage("mr_uses_group"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetPass {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetPass")
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
							tq.SetHeaderSessionID(startPacket.Header.SessionID),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueFlag(authenContinueFlag),
							tq.SetAuthenContinueUserMessage("Continue inside"),
							tq.SetAuthenContinueData("foo"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusFail {
						spew.Dump(body)
						return fmt.Errorf("expecting a authenStatusFail because client sent an abort")
					}
					return nil
				},
			},
		},
	}
	startPacket = BuildASCIIStartPacket()
	onPassword := Test{
		Name:   "test authen abort on request to send password",
		Secret: []byte("fooman"),
		Seq: []Sequence{
			{
				Packet: startPacket,
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetUser {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetUser")
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
							tq.SetHeaderSessionID(startPacket.Header.SessionID),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueUserMessage("mr_uses_group"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetPass {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetPass")
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
							tq.SetHeaderSeqNo(7),
							tq.SetHeaderSessionID(startPacket.Header.SessionID),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueFlag(tq.AuthenContinueFlagAbort),
							tq.SetAuthenContinueUserMessage("Continue inside"),
							tq.SetAuthenContinueData("foo"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusFail {
						spew.Dump(body)
						return fmt.Errorf("expecting a authenStatusFail because client sent an abort")
					}
					return nil
				},
			},
		},
	}
	tests := []Test{
		onStart,
		onUser,
		onPassword,
	}
	return tests
}

// GetASCIIEnableAbortTests ...
func GetASCIIEnableAbortTests() []Test {
	startPacket := BuildASCIIStartPacket()
	onStart := Test{
		Name:   "test authen abort on first client packet",
		Secret: []byte("fooman"),
		Seq: []Sequence{
			{
				Packet: startPacket,
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetUser {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetUser")
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
							tq.SetHeaderSessionID(startPacket.Header.SessionID),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueFlag(tq.AuthenContinueFlagAbort),
							tq.SetAuthenContinueUserMessage("Continue inside"),
							tq.SetAuthenContinueData("foo"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusFail {
						spew.Dump(body)
						return fmt.Errorf("expecting a authenStatusFail because client sent an abort")
					}
					return nil
				},
			},
		},
	}
	onUser := Test{
		Name:   "test authen abort on user sending username",
		Secret: []byte("fooman"),
		Seq: []Sequence{
			{
				Packet: tq.NewPacket(
					tq.SetPacketHeader(
						tq.NewHeader(
							tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
							tq.SetHeaderType(tq.Authenticate),
							tq.SetHeaderSessionID(12346),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenStart(
							tq.SetAuthenStartAction(tq.AuthenActionLogin),
							tq.SetAuthenStartPrivLvl(tq.PrivLvlUser),
							tq.SetAuthenStartType(tq.AuthenTypeASCII),
							tq.SetAuthenStartService(tq.AuthenServiceEnable),
							tq.SetAuthenStartPort("tty0"),
							tq.SetAuthenStartRemAddr("foo"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetUser {
						return fmt.Errorf("failed to match AuthenStatusGetUser")
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
							tq.SetHeaderSessionID(12346),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueUserMessage("mr_uses_group"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetPass {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetPass")
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
							tq.SetHeaderSessionID(12346),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueFlag(tq.AuthenContinueFlagAbort),
							tq.SetAuthenContinueUserMessage("Continue inside"),
							tq.SetAuthenContinueData("foo"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusFail {
						spew.Dump(body)
						return fmt.Errorf("expecting a authenStatusFail because client sent an abort")
					}
					return nil
				},
			},
		},
	}
	startPacket = BuildASCIIStartPacket()
	onPassword := Test{
		Name:   "test authen abort on user sending password",
		Secret: []byte("fooman"),
		Seq: []Sequence{
			{
				Packet: startPacket,
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetUser {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetUser")
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
							tq.SetHeaderSessionID(startPacket.Header.SessionID),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueUserMessage("mr_uses_group"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusGetPass {
						spew.Dump(body)
						return fmt.Errorf("failed to match AuthenStatusGetPass")
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
							tq.SetHeaderSessionID(startPacket.Header.SessionID),
						),
					),
					tq.SetPacketBodyUnsafe(
						tq.NewAuthenContinue(
							tq.SetAuthenContinueFlag(tq.AuthenContinueFlagAbort),
							tq.SetAuthenContinueUserMessage("Continue inside"),
							tq.SetAuthenContinueData("foo"),
						),
					),
				),
				ValidateBody: func(response []byte) error {
					var body tq.AuthenReply
					if err := tq.Unmarshal(response, &body); err != nil {
						return err
					}
					if body.Status != tq.AuthenStatusFail {
						spew.Dump(body)
						return fmt.Errorf("expecting a authenStatusFail because client sent an abort")
					}
					return nil
				},
			},
		},
	}
	tests := []Test{
		onStart,
		onUser,
		onPassword,
	}
	return tests
}
