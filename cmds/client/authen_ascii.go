/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

// Package main provides a basic tacacs test client for use with tacacs servers and tacquito
package main

import (
	"fmt"
	"os"

	tq "github.com/facebookincubator/tacquito"
)

type asciiSequence struct {
	packet   *tq.Packet
	validate func(response []byte)
}

func ascii(c *tq.Client) {
	fmt.Println("execute ascii authentication")
	var resp *tq.Packet
	var err error
	for _, s := range newASCIIAuthenSequence(getPassword()) {
		resp, err = c.Send(s.packet)
		if err != nil {
			fmt.Printf("%v\n", err)
			os.Exit(1)
		}
		s.validate(resp.Body)
	}
	printASCIIResponse(resp)
}
func newASCIIAuthenSequence(password string) []asciiSequence {
	authenRequest := asciiSequence{
		packet: tq.NewPacket(
			tq.SetPacketHeader(
				tq.NewHeader(
					tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
					tq.SetHeaderType(tq.Authenticate),
					tq.SetHeaderSessionID(12345),
				),
			),
			tq.SetPacketBodyUnsafe(
				tq.NewAuthenStart(
					tq.SetAuthenStartAction(tq.AuthenActionLogin),
					tq.SetAuthenStartPrivLvl(tq.PrivLvlUser),
					tq.SetAuthenStartType(tq.AuthenTypeASCII),
					tq.SetAuthenStartService(tq.AuthenServiceLogin),
					tq.SetAuthenStartPort(tq.AuthenPort("tty0")),
					tq.SetAuthenStartRemAddr(tq.AuthenRemAddr("devvm2515")),
				),
			),
		),
		validate: func(response []byte) {
			var body tq.AuthenReply
			if err := tq.Unmarshal(response, &body); err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
			if body.Status != tq.AuthenStatusGetUser {
				fmt.Println("failed to match AuthenStatusGetUser")
				os.Exit(1)
			}
		},
	}

	authenContinueUsername := asciiSequence{
		packet: tq.NewPacket(
			tq.SetPacketHeader(
				tq.NewHeader(
					tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
					tq.SetHeaderType(tq.Authenticate),
					tq.SetHeaderSeqNo(3),
					tq.SetHeaderSessionID(12345),
				),
			),
			tq.SetPacketBodyUnsafe(
				tq.NewAuthenContinue(
					tq.SetAuthenContinueUserMessage(tq.AuthenUserMessage(*username)),
				),
			),
		),
		validate: func(response []byte) {
			var body tq.AuthenReply
			if err := tq.Unmarshal(response, &body); err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
			if body.Status != tq.AuthenStatusGetPass {
				fmt.Println("failed to match AuthenStatusGetPass")
				os.Exit(1)
			}
		},
	}

	authenContinuePassword := asciiSequence{
		packet: tq.NewPacket(
			tq.SetPacketHeader(
				tq.NewHeader(
					tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
					tq.SetHeaderType(tq.Authenticate),
					tq.SetHeaderSeqNo(5),
					tq.SetHeaderSessionID(12345),
				),
			),
			tq.SetPacketBodyUnsafe(
				tq.NewAuthenContinue(
					tq.SetAuthenContinueUserMessage(tq.AuthenUserMessage(*username)),
				),
			),
		),
		validate: func(response []byte) {
			var body tq.AuthenReply
			if err := tq.Unmarshal(response, &body); err != nil {
				fmt.Printf("%v", err)
				os.Exit(1)
			}
			if body.Status != tq.AuthenStatusPass {
				fmt.Println("failed to match AuthenStatusPass")
				os.Exit(1)
			}
		},
	}
	return []asciiSequence{
		authenRequest,
		authenContinueUsername,
		authenContinuePassword,
	}
}

func printASCIIResponse(resp *tq.Packet) {
	var body tq.AuthenReply
	if err := tq.Unmarshal(resp.Body, &body); err != nil {
		fmt.Printf("\n%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n%+v\n", body)
}
