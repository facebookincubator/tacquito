/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import "fmt"

// NB a general note on encoding. Tacacs is generally a text protocol, eg:
// https://datatracker.ietf.org/doc/html/rfc8907#section-3.7
//
// There are exceptions though.
//
//  The TACACS+ protocol makes extensive use of text strings.  "The
//  Draft" intended that these strings would be treated as byte arrays
//  where each byte would represent a US-ASCII character.

//  More recently, server implementations have been extended to interwork
//  with external identity services, and so a more nuanced approach is
//  needed.  Usernames MUST be encoded and handled using the
//  UsernameCasePreserved Profile specified in [RFC8265].  The security
//  considerations in Section 8 of [RFC8265] apply.

//  Where specifically mentioned, data fields contain arrays of arbitrary
//  bytes as required for protocol processing.  These are not intended to
//  be made visible through user interface to users.

//  All other text fields in TACACS+ MUST be treated as printable byte
//  arrays of US-ASCII as defined by [RFC0020].  The term "printable"
//  used here means the fields MUST exclude the "Control Characters"
//  defined in Section 5.2 of [RFC0020].
//
// If not confusing, somewhat confusing.  We default to ASCII always, but
// there are times where []byte is allowed, which we won't enforce ASCII

// AuthenAction indicates the authentication Action.  Legal values are listed below.
type AuthenAction uint8

const (
	// AuthenActionLogin per rfc
	AuthenActionLogin AuthenAction = 0x01
	// AuthenActionPass per rfc
	AuthenActionPass AuthenAction = 0x02
	// AuthenActionSendAuth per rfc
	AuthenActionSendAuth AuthenAction = 0x04
)

// Validate characterics of type based on rfc and usage.
func (t AuthenAction) Validate(condition interface{}) error {
	switch t {
	case AuthenActionLogin, AuthenActionPass, AuthenActionSendAuth:
		return nil
	}
	return fmt.Errorf("unknown AuthenAction value [%v]", t)
}

// Len returns the length of AuthenAction.
func (t AuthenAction) Len() int {
	return 1
}

// String returns AuthenAction as a string.
func (t AuthenAction) String() string {
	switch t {
	case AuthenActionLogin:
		return "AuthenActionLogin"
	case AuthenActionPass:
		return "AuthenActionPass"
	case AuthenActionSendAuth:
		return "AuthenActionSendAuth"
	}
	return fmt.Sprintf("unknown AuthenAction[%d]", uint8(t))
}

// PrivLvl indicates the privilege level that the User is authenticating
// as. Please refer to https://datatracker.ietf.org/doc/html/rfc8907#section-9
type PrivLvl uint8

const (
	// PrivLvlMin per rfc
	PrivLvlMin PrivLvl = 0x0
	// PrivLvlUser per rfc
	PrivLvlUser PrivLvl = 0x01
	// PrivLvlRoot per rfc
	PrivLvlRoot PrivLvl = 0x0f
	// PrivLvlMax per rfc
	PrivLvlMax PrivLvl = 0x0f
)

// Len returns the length of PrivLvl.
func (t PrivLvl) Len() int {
	return 1
}

// Validate has a valid range of 0-15
func (t PrivLvl) Validate(condition interface{}) error {
	if t <= 15 {
		return nil
	}
	return fmt.Errorf("invalid PrivLvl: [%v]", t)
}

// String returns PrivLvl as string.
func (t PrivLvl) String() string {
	switch t {
	case PrivLvlMin:
		return "PrivLvlMin"
	case PrivLvlUser:
		return "PrivLvlUser"
	case PrivLvlRoot:
		return "PrivLvlRoot"
	}
	return fmt.Sprintf("unknown PrivLvl[%d]", uint8(t))
}

// AuthenType is the type of authentication.
type AuthenType uint8

const (
	// AuthenTypeNotSet only valid for Authorization/Accounting Requests (https://datatracker.ietf.org/doc/html/rfc8907#section-6.1)
	AuthenTypeNotSet AuthenType = 0x00
	// AuthenTypeASCII per rfc
	AuthenTypeASCII AuthenType = 0x01
	// AuthenTypePAP per rfc
	AuthenTypePAP AuthenType = 0x02
	// AuthenTypeCHAP per rfc
	AuthenTypeCHAP AuthenType = 0x03
	// AuthenTypeARAP per rfc
	AuthenTypeARAP AuthenType = 0x04
	// AuthenTypeMSCHAP per rfc
	AuthenTypeMSCHAP AuthenType = 0x05
	// AuthenTypeMSCHAPV2 per rfc
	AuthenTypeMSCHAPV2 AuthenType = 0x06
)

// Validate characterics of type based on rfc and usage.
// Validate characterics of type based on rfc and usage.
func (t AuthenType) Validate(condition interface{}) error {
	switch t {
	case AuthenTypeNotSet, AuthenTypeASCII, AuthenTypePAP, AuthenTypeCHAP, AuthenTypeARAP, AuthenTypeMSCHAP, AuthenTypeMSCHAPV2:
		return nil
	}
	return fmt.Errorf("unknown AuthenType value [%v]", t)
}

// Len returns the length of AuthenType.
func (t AuthenType) Len() int {
	return 1
}

// String returns AuthenType as a string.
func (t AuthenType) String() string {
	switch t {
	case AuthenTypeNotSet:
		return "AuthenTypeNotSet"
	case AuthenTypeASCII:
		return "AuthenTypeASCII"
	case AuthenTypePAP:
		return "AuthenTypePAP"
	case AuthenTypeCHAP:
		return "AuthenTypeCHAP"
	case AuthenTypeARAP:
		return "AuthenTypeARAP"
	case AuthenTypeMSCHAP:
		return "AuthenTypeMSCHAP"
	case AuthenTypeMSCHAPV2:
		return "AuthenTypeMSCHAPV2"
	}
	return fmt.Sprintf("unknown AuthenType[%d]", uint8(t))
}

// AuthenService is the service that is requesting the authentication.
type AuthenService uint8

const (
	// AuthenServiceNone is intended for the authorization application of this field
	// that indicates that no authentication was performed by the device.
	AuthenServiceNone AuthenService = 0x00
	// AuthenServiceLogin indicates regular login (as opposed to ENABLE) to a client device.
	AuthenServiceLogin AuthenService = 0x01
	// AuthenServiceEnable identifies the ENABLE AuthenService, which refers to a service
	// requesting authentication in order to grant the User different privileges. This
	// is comparable to the Unix "su(1)" command, which substitutes the current User's
	// identity with another. An AuthenService value of AuthenServiceNone is only to be
	// used when none of the other AuthenService values are appropriate.
	AuthenServiceEnable AuthenService = 0x02
	// AuthenServicePPP per rfc
	AuthenServicePPP AuthenService = 0x03
	// AuthenServiceARAP per rfc
	AuthenServiceARAP AuthenService = 0x04
	// AuthenServicePT per rfc
	AuthenServicePT AuthenService = 0x05
	// AuthenServiceRCMD per rfc
	AuthenServiceRCMD AuthenService = 0x06
	// AuthenServiceX25 per rfc
	AuthenServiceX25 AuthenService = 0x07
	// AuthenServiceNASI per rfc
	AuthenServiceNASI AuthenService = 0x08
	// AuthenServiceFwProxy per rfc
	AuthenServiceFwProxy AuthenService = 0x09
)

// Validate characterics of type based on rfc and usage.
func (t AuthenService) Validate(condition interface{}) error {
	switch t {
	case AuthenServiceNone, AuthenServiceLogin, AuthenServiceEnable, AuthenServicePPP, AuthenServiceARAP, AuthenServicePT, AuthenServiceRCMD, AuthenServiceX25, AuthenServiceNASI, AuthenServiceFwProxy:
		return nil
	}
	return fmt.Errorf("unknown AuthenService value [%v]", t)
}

// Len returns the length of AuthenService.
func (t AuthenService) Len() int {
	return 1
}

// String returns AuthenService as a string.
func (t AuthenService) String() string {
	switch t {
	case AuthenServiceNone:
		return "AuthenServiceNone"
	case AuthenServiceLogin:
		return "AuthenServiceLogin"
	case AuthenServiceEnable:
		return "AuthenServiceEnable"
	case AuthenServicePPP:
		return "AuthenServicePPP"
	case AuthenServiceARAP:
		return "AuthenServiceARAP"
	case AuthenServicePT:
		return "AuthenServicePT"
	case AuthenServiceRCMD:
		return "AuthenServiceRCMD"
	case AuthenServiceX25:
		return "AuthenServiceX25"
	case AuthenServiceNASI:
		return "AuthenServiceNASI"
	case AuthenServiceFwProxy:
		return "AuthenServiceFwProxy"
	}
	return fmt.Sprintf("unknown AuthenService[%d]", uint8(t))
}

// AuthenStatus is the current status of the authentication.
type AuthenStatus uint8

const (
	// AuthenStatusPass per rfc
	AuthenStatusPass AuthenStatus = 0x01
	// AuthenStatusFail per rfc
	AuthenStatusFail AuthenStatus = 0x02
	// AuthenStatusGetData per rfc
	AuthenStatusGetData AuthenStatus = 0x03
	// AuthenStatusGetUser per rfc
	AuthenStatusGetUser AuthenStatus = 0x04
	// AuthenStatusGetPass per rfc
	AuthenStatusGetPass AuthenStatus = 0x05
	// AuthenStatusRestart per rfc
	AuthenStatusRestart AuthenStatus = 0x06
	// AuthenStatusError per rfc
	AuthenStatusError AuthenStatus = 0x07
)

// Validate characterics of type based on rfc and usage.
func (t AuthenStatus) Validate(condition interface{}) error {
	switch t {
	case AuthenStatusPass, AuthenStatusFail, AuthenStatusGetData, AuthenStatusGetUser, AuthenStatusGetPass, AuthenStatusRestart, AuthenStatusError:
		return nil
	}
	return fmt.Errorf("unknown AuthenStatus value [%v]", t)
}

// Len returns the length of AuthenStatus.
func (t AuthenStatus) Len() int {
	return 1
}

// String returns AuthenStatus as a string.
func (t AuthenStatus) String() string {
	switch t {
	case AuthenStatusPass:
		return "AuthenStatusPass"
	case AuthenStatusFail:
		return "AuthenStatusFail"
	case AuthenStatusGetData:
		return "AuthenStatusGetData"
	case AuthenStatusGetUser:
		return "AuthenStatusGetUser"
	case AuthenStatusGetPass:
		return "AuthenStatusGetPass"
	case AuthenStatusRestart:
		return "AuthenStatusRestart"
	case AuthenStatusError:
		return "AuthenStatusError"
	}
	return fmt.Sprintf("unknown AuthenStatus[%d]", uint8(t))
}

// AuthenServerMsg see packet type for use information.
type AuthenServerMsg string

// Validate characterics of type based on rfc and usage.
func (t AuthenServerMsg) Validate(condition interface{}) error {
	return nil
}

// Len returns the length of AuthenServerMsg.
func (t AuthenServerMsg) Len() int {
	return len(t)
}

// String returns AuthenServerMsg as a string.
func (t AuthenServerMsg) String() string {
	return string(t)
}

// AuthenUserMessage - this field is the string that the user entered, or the client
// provided on behalf of the user, in response to the server_msg from a
// REPLY packet. The user_len indicates the length of the user field,
// in bytes.
type AuthenUserMessage string

// Validate characterics of type based on rfc and usage.
func (t AuthenUserMessage) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthenUserMessage is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthenUserMessage.
func (t AuthenUserMessage) Len() int {
	return len(t)
}

// String maps AuthenUserMessage to string.
func (t AuthenUserMessage) String() string {
	return string(t)
}

// AuthenData - This field carries information that is specific to the action and the
// authen_type for this session. Valid uses of this field are described
// below. The data_len indicates the length of the data field, in
// bytes.
type AuthenData string

// Len returns the length of AuthenData.
func (t AuthenData) Len() int {
	return len(t)
}

// Validate length of value
func (t AuthenData) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-5.4.2
	// In an ascii login, this must be ascii, but in other's it is per rfc8907
	switch atype := condition.(type) {
	case AuthenType:
		switch atype {
		case AuthenTypeASCII:
			if !isAllASCII(string(t)) {
				return fmt.Errorf("AuthenData is not all ascii, but it must be for AuthenTypeASCII, [%v]", t)
			}
		}
	}
	return nil
}

// String maps AuthenData to string.
func (t AuthenData) String() string {
	return string(t)
}

// AuthenUser see packet type for use information.
type AuthenUser string

// Validate characterics of type based on rfc and usage.
func (t AuthenUser) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthenUser is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthenUser.
func (t AuthenUser) Len() int {
	return len(t)
}

// String returns AuthenUser as a string.
func (t AuthenUser) String() string {
	return string(t)
}

// AuthenPort see packet type for use information.
type AuthenPort string

// Validate characterics of type based on rfc and usage.
func (t AuthenPort) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthenPort is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthenPort.
func (t AuthenPort) Len() int {
	return len(t)
}

// String returns AuthenPort as a string.
func (t AuthenPort) String() string {
	return string(t)
}

// AuthenRemAddr see packet type for use information.
type AuthenRemAddr string

// Validate characterics of type based on rfc and usage.
func (t AuthenRemAddr) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthenRemAddr is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthenRemAddr.
func (t AuthenRemAddr) Len() int {
	return len(t)
}

// String returns AuthenRemAddr as a string.
func (t AuthenRemAddr) String() string {
	return string(t)
}

// AuthenReplyFlag flags that modify the action to be taken.
type AuthenReplyFlag uint8

const (
	// AuthenReplyFlagNoEcho per rfc
	AuthenReplyFlagNoEcho AuthenReplyFlag = 0x01
)

// Set AuthenReplyFlag's f bit.
func (b *AuthenReplyFlag) Set(f AuthenReplyFlag) { *b = *b | f }

// Clear AuthenReplyFlag's f bit.
func (b *AuthenReplyFlag) Clear(f AuthenReplyFlag) { *b = *b &^ f }

// Toggle AuthenReplyFlag's f bit.
func (b *AuthenReplyFlag) Toggle(f AuthenReplyFlag) { *b = *b ^ f }

// Has returns true when b has the f bit set.
func (b *AuthenReplyFlag) Has(f AuthenReplyFlag) bool { return *b&f != 0 }

// String to satisfy Fields interface
func (b AuthenReplyFlag) String() string {
	if b.Has(AuthenReplyFlagNoEcho) {
		return "AuthenReplyFlagNoEcho"
	}
	return ""
}

// AuthenContinueFlag flags that modify the action to be taken.
type AuthenContinueFlag uint8

const (
	// AuthenContinueFlagAbort per rfc
	AuthenContinueFlagAbort AuthenContinueFlag = 0x01
)

// Set AuthenContinueFlag's f bit.
func (b *AuthenContinueFlag) Set(f AuthenContinueFlag) { *b = *b | f }

// Clear AuthenContinueFlag's f bit.
func (b *AuthenContinueFlag) Clear(f AuthenContinueFlag) { *b = *b &^ f }

// Toggle AuthenContinueFlag's f bit.
func (b *AuthenContinueFlag) Toggle(f AuthenContinueFlag) { *b = *b ^ f }

// Has returns true when b has the f bit set.
func (b *AuthenContinueFlag) Has(f AuthenContinueFlag) bool { return *b&f != 0 }

// String to satisfy Fields interface
func (b AuthenContinueFlag) String() string {
	if b.Has(AuthenContinueFlagAbort) {
		return "AuthenContinueFlagAbort"
	}
	return ""
}
