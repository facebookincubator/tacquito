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

func pap(c *tq.Client) {
	fmt.Println("execute pap authentication")
	req := newPAPRequest(getPassword())
	resp, err := c.Send(req)
	if err != nil {
		fmt.Printf("%v\n", err)
		os.Exit(1)
	}
	printPAPResponse(resp)
}

func newPAPRequest(password string) *tq.Packet {
	return tq.NewPacket(
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
				tq.SetAuthenStartPrivLvl(tq.PrivLvl(*privLvl)),
				tq.SetAuthenStartPort(tq.AuthenPort(*port)),
				tq.SetAuthenStartRemAddr(tq.AuthenRemAddr(*remAddr)),
				tq.SetAuthenStartUser(tq.AuthenUser(*username)),
				tq.SetAuthenStartData(tq.AuthenData(password)),
			),
		),
	)
}

func printPAPResponse(resp *tq.Packet) {
	var body tq.AuthenReply
	if err := tq.Unmarshal(resp.Body, &body); err != nil {
		fmt.Printf("\n%v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n%+v\n", body)
}
