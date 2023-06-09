/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// AuthenMethod per rfc and terribly named. Should read AuthorMethod, but rfc
// defines it as authen_method.
type AuthenMethod uint8

const (
	// AuthenMethodNotSet per rfc
	AuthenMethodNotSet AuthenMethod = 0x0
	// AuthenMethodNone per rfc
	AuthenMethodNone AuthenMethod = 0x01
	// AuthenMethodKrb5 per rfc
	AuthenMethodKrb5 AuthenMethod = 0x02
	// AuthenMethodLine per rfc
	AuthenMethodLine AuthenMethod = 0x03
	// AuthenMethodEnable per rfc
	AuthenMethodEnable AuthenMethod = 0x04
	// AuthenMethodLocal per rfc
	AuthenMethodLocal AuthenMethod = 0x05
	// AuthenMethodTacacsPlus per rfc
	AuthenMethodTacacsPlus AuthenMethod = 0x06
	// AuthenMethodGuest per rfc
	AuthenMethodGuest AuthenMethod = 0x08
	// AuthenMethodRadius per rfc
	AuthenMethodRadius AuthenMethod = 0x10
)

// Validate characterics of type based on rfc and usage.
func (t AuthenMethod) Validate(condition interface{}) error {
	switch t {
	case AuthenMethodNotSet, AuthenMethodNone, AuthenMethodKrb5, AuthenMethodLine, AuthenMethodEnable, AuthenMethodLocal, AuthenMethodTacacsPlus, AuthenMethodGuest, AuthenMethodRadius:
		return nil
	}
	return fmt.Errorf("unknown AuthenMethod value [%v]", t)
}

// Len returns the length of AuthenMethod.
func (t AuthenMethod) Len() int {
	return 1
}

// String returns AuthenMethod as a string.
func (t AuthenMethod) String() string {
	switch t {
	case AuthenMethodNotSet:
		return "AuthenMethodNotSet"
	case AuthenMethodNone:
		return "AuthenMethodNone"
	case AuthenMethodKrb5:
		return "AuthenMethodKrb5"
	case AuthenMethodLine:
		return "AuthenMethodLine"
	case AuthenMethodEnable:
		return "AuthenMethodEnable"
	case AuthenMethodLocal:
		return "AuthenMethodLocal"
	case AuthenMethodTacacsPlus:
		return "AuthenMethodTacacsPlus"
	case AuthenMethodGuest:
		return "AuthenMethodGuest"
	case AuthenMethodRadius:
		return "AuthenMethodRadius"
	}
	return fmt.Sprintf("unknown AuthenMethod[%d]", uint8(t))
}

// Arg per rfc, The arguments describe the specifics of the authorization that is being requested.
type Arg string

// Validate characterics of type based on rfc and usage.
func (t Arg) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if !isAllASCII(string(t)) {
		return fmt.Errorf("Arg is not all ascii, but it must be, [%v]", t)
	}

	if len(t) < 2 || len(t) > 255 {
		return fmt.Errorf("invalid arg length. valid range [2-255], found [%v]", len(t))
	}
	return nil
}

// Len returns the length of Arg.
func (t Arg) Len() int {
	return len(t)
}

// String returns Arg as a string, with all leading and trailing white space removed, as defined by Unicode.
func (t Arg) String() string {
	return strings.TrimSpace(string(t))
}

// ASV splits an attribute value pair into attribute, separator, value
func (t Arg) ASV() (string, string, string) {
	s := t.String()
	i := strings.IndexAny(s, "=*")
	if i < 0 {
		return "", "", ""
	}
	return s[:i], string(s[i]), s[i+1:]
}

// Args come from the client argument fields

// Args is a helper type used when dealing with string args that have been converted to Arg types
type Args []Arg

// Len returns the length of Args.
func (t Args) Len() int {
	return len(t)
}

// Validate is all ASCII
func (t Args) Validate(condition interface{}) error {
	for _, arg := range t {
		if !isAllASCII(string(arg)) {
			return fmt.Errorf("Args are not all ASCII")
		}
	}
	return nil
}

// String returns Args as string, ignoring <cr> cmd-arg=<cr>
func (t Args) String() string {
	var b strings.Builder
	for _, arg := range t {
		fmt.Fprintf(&b, "%s, ", arg)
	}
	return b.String()
}

// Service joins all service args into a single string.
func (t Args) Service() string {
	var s string
	for _, arg := range t {
		a, _, v := arg.ASV()
		if a == "service" {
			return v
		}
	}
	return s
}

// CommandSplit returns the attribute, separator and value of
// cmd= or cmd* or cmd=show or cmd*show.  Zero values are returned
// if not found
func (t Args) CommandSplit() (string, string, string) {
	for _, arg := range t {
		a, s, v := arg.ASV()
		if a == "cmd" {
			return a, s, v
		}
	}
	return "", "", ""
}

// Command returns the cmd only if cmd=foo or cmd= or cmd*, etc is provided
// the delimiter is immaterial to this function returning a value
// the returned value will be a zero value if cmd is not present
func (t Args) Command() string {
	var cmd string
	for _, arg := range t {
		a, _, v := arg.ASV()
		if a == "cmd" {
			return v
		}
	}
	return cmd
}

// CommandArgs joins all cmd-arg args into a single string.
func (t Args) CommandArgs() string {
	args := make([]string, 0, len(t))
	for _, arg := range t {
		a, _, v := arg.ASV()
		if a == "cmd-arg" {
			args = append(args, v)
		}
	}
	return strings.Join(args, " ")
}

// Args splits the Args into cmd, cmd-arg and other=arg
// the key is the left side of the delimiter, etc
func (t Args) Args() []string {
	unique := t.Unique()
	args := make([]string, 0, len(unique))
	for _, arg := range unique {
		args = append(args, arg.String())
	}
	return args
}

// Unique will filter out duplicate args, if any are found
func (t Args) Unique() Args {
	seen := make(map[string]struct{})
	args := make(Args, 0, len(t))
	for _, arg := range t {
		asv := arg.String()
		if _, ok := seen[asv]; ok {
			// filter duplicate asv if found
			continue
		}
		seen[asv] = struct{}{}
		args = append(args, arg)
	}
	return args
}

// Append will append arg strings to t and convert them to Arg in the process
func (t *Args) Append(args ...string) {
	for _, arg := range args {
		*t = append(*t, Arg(arg))
	}
}

// AuthorStatus indicates the authorization status
// https://datatracker.ietf.org/doc/html/rfc8907#section-6.2
type AuthorStatus uint8

const (
	// AuthorStatusPassAdd per rfc
	AuthorStatusPassAdd AuthorStatus = 0x01
	// AuthorStatusPassRepl per rfc
	AuthorStatusPassRepl AuthorStatus = 0x02
	// AuthorStatusFail per rfc
	AuthorStatusFail AuthorStatus = 0x10
	// AuthorStatusError per rfc
	AuthorStatusError AuthorStatus = 0x11
)

// Validate characterics of type based on rfc and usage.
func (t AuthorStatus) Validate(condition interface{}) error {
	switch t {
	case AuthorStatusPassAdd, AuthorStatusPassRepl, AuthorStatusFail, AuthorStatusError:
		return nil
	}
	return fmt.Errorf("unknown AuthorStatus value [%v]", t)
}

// Len returns the length of AuthorStatus.
func (t AuthorStatus) Len() int {
	return 1
}

// String returns AuthorStatus as a string.
func (t AuthorStatus) String() string {
	switch t {
	case AuthorStatusPassAdd:
		return "AuthorStatusPassAdd"
	case AuthorStatusPassRepl:
		return "AuthorStatusPassRepl"
	case AuthorStatusFail:
		return "AuthorStatusFail"
	case AuthorStatusError:
		return "AuthorStatusError"
	}
	return fmt.Sprintf("unknown AuthorStatus[%d]", uint8(t))
}

// AuthorServerMsg a printable US-ASCII string that may be presented to theuser.
type AuthorServerMsg string

// Validate characterics of type based on rfc and usage.
func (t AuthorServerMsg) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthorServerMsg is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthorServerMsg.
func (t AuthorServerMsg) Len() int {
	return len(t)
}

// String returns AuthorServerMsg as a string.
func (t AuthorServerMsg) String() string {
	return string(t)
}

// AuthorData is a printable US-ASCII string that may be presented on an
// administrative display, console or log.  The decision to present this
// message is client specific.
type AuthorData string

// Validate characterics of type based on rfc and usage.
func (t AuthorData) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthorData is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthorData.
func (t AuthorData) Len() int {
	return len(t)
}

// String returns AuthorData as a string.
func (t AuthorData) String() string {
	return string(t)
}

// AuthorService the primary service.  Specifying a service argument indicates that
// this is a request for authorization or accounting of that service.
// For example: "shell", "tty-server", "connection", "system" and
// "firewall"; others may be chosen for the required application.
// This argument MUST always be included.
// https://datatracker.ietf.org/doc/html/rfc8907#section-8.2
type AuthorService string

// Validate characterics of type based on rfc and usage.
func (t AuthorService) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthorService is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthorService.
func (t AuthorService) Len() int {
	return len(t)
}

// String returns AuthorService as a string.
func (t AuthorService) String() string {
	return string(t)
}

// AuthorProtocol A field that may be used to indicate a subset of a service.
// https://datatracker.ietf.org/doc/html/rfc8907#section-8.2
type AuthorProtocol string

// Validate characterics of type based on rfc and usage.
func (t AuthorProtocol) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthorProtocol is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthorProtocol.
func (t AuthorProtocol) Len() int {
	return len(t)
}

// String returns AuthorProtocol as a string.
func (t AuthorProtocol) String() string {
	return string(t)
}

// AuthorCmd A shell (exec) command. This indicates the command name of the
// command that is to be run. The "cmd" argument MUST be specified
// if service equals "shell".
//
// Authorization of shell commands is a common use case for the
// TACACS+ protocol. Command Authorization generally takes one of
// two forms: session based or command based.
//
// For session-based shell authorization, the "cmd" argument will
// have an empty value. The client determines which commands are
// allowed in a session according to the arguments present in the
// authorization.
//
// In command-based authorization, the client requests that the
// server determine whether a command is allowed by making an
// authorization request for each command. The "cmd" argument will
// have the command name as its value.
// https://datatracker.ietf.org/doc/html/rfc8907#section-8.2
type AuthorCmd string

// Validate characterics of type based on rfc and usage.
func (t AuthorCmd) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthorCmd is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthorCmd.
func (t AuthorCmd) Len() int {
	return len(t)
}

// String returns AuthorCmd as a string.
func (t AuthorCmd) String() string {
	return string(t)
}

// AuthorCmdArg An argument to a shell (exec) command. This indicates an argument
// for the shell command that is to be run. Multiple cmd-arg
// arguments may be specified, and they are order dependent.
// https://datatracker.ietf.org/doc/html/rfc8907#section-8.2
type AuthorCmdArg string

// Validate characterics of type based on rfc and usage.
func (t AuthorCmdArg) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthorCmdArg is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthorCmdArg.
func (t AuthorCmdArg) Len() int {
	return len(t)
}

// String returns AuthorCmdArg as a string.
func (t AuthorCmdArg) String() string {
	return string(t)
}

// AuthorACL A number representing a connection access list. Applicable only
// to session-based shell authorization. For details of text
// encoding, see "Treatment of Text Strings" (Section 3.7).
// https://datatracker.ietf.org/doc/html/rfc8907#section-8.2
// https://datatracker.ietf.org/doc/html/rfc8907#section-3.7
type AuthorACL int

// Validate characterics of type based on rfc and usage.
func (t AuthorACL) Validate(condition interface{}) error {
	return nil
}

// Len returns the length of AuthorACL.
func (t AuthorACL) Len() int {
	return 1
}

// String returns AuthorACL as a string.
func (t AuthorACL) String() string {
	return fmt.Sprint(int(t))
}

// AuthorInACL The identifier (name) of an interface input access list. For
// details of text encoding, see "Treatment of Text Strings" (Section 3.7).
// https://datatracker.ietf.org/doc/html/rfc8907#section-8.2
// https://datatracker.ietf.org/doc/html/rfc8907#section-3.7
type AuthorInACL string

// Validate characterics of type based on rfc and usage.
func (t AuthorInACL) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthorInACL is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthorInACL.
func (t AuthorInACL) Len() int {
	return len(t)
}

// String returns AuthorInACL as a string.
func (t AuthorInACL) String() string {
	return string(t)
}

// AuthorOutACL The identifier (name) of an interface output access list. For
// details of text encoding, see "Treatment of Text Strings" (Section 3.7).
// https://datatracker.ietf.org/doc/html/rfc8907#section-8.2
// https://datatracker.ietf.org/doc/html/rfc8907#section-3.7
type AuthorOutACL string

// Validate characterics of type based on rfc and usage.
func (t AuthorOutACL) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthorOutACL is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthorOutACL.
func (t AuthorOutACL) Len() int {
	return len(t)
}

// String returns AuthorOutACL as a string.
func (t AuthorOutACL) String() string {
	return string(t)
}

// AuthorAddr A network address.
// https://datatracker.ietf.org/doc/html/rfc8907#section-3.7
type AuthorAddr net.IP

// Validate characterics of type based on rfc and usage.
func (t AuthorAddr) Validate(condition interface{}) error {
	return nil
}

// Len returns the length of AuthorAddr.
func (t AuthorAddr) Len() int {
	return len(t)
}

// String returns AuthorAddr as a string.
func (t AuthorAddr) String() string {
	return string(t)
}

// AuthorAddrPool The identifier of an address pool from which the client can assign an address.
// https://datatracker.ietf.org/doc/html/rfc8907#section-3.7
type AuthorAddrPool string

// Validate characterics of type based on rfc and usage.
func (t AuthorAddrPool) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthorAddrPool is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthorAddrPool.
func (t AuthorAddrPool) Len() int {
	return len(t)
}

// String returns AuthorAddrPool as a string.
func (t AuthorAddrPool) String() string {
	return string(t)
}

// AuthorTimeout An absolute timer for the connection (in minutes). A value of zero indicates no timeout.
// https://datatracker.ietf.org/doc/html/rfc8907#section-8.2
type AuthorTimeout int

// Validate characterics of type based on rfc and usage.
func (t AuthorTimeout) Validate(condition interface{}) error {
	return nil
}

// Len returns the length of AuthorTimeout.
func (t AuthorTimeout) Len() int {
	return 1
}

// String returns AuthorTimeout as a string.
func (t AuthorTimeout) String() string {
	return fmt.Sprint(int(t))
}

// AuthorIdleTime An idle-timeout for the connection (in minutes). A value of zero indicates no timeout.
// https://datatracker.ietf.org/doc/html/rfc8907#section-8.2
type AuthorIdleTime int

// Validate characterics of type based on rfc and usage.
func (t AuthorIdleTime) Validate(condition interface{}) error {
	return nil
}

// Len returns the length of AuthorIdleTime.
func (t AuthorIdleTime) Len() int {
	return 1
}

// String returns AuthorIdleTime as a string.
func (t AuthorIdleTime) String() string {
	return fmt.Sprint(int(t))
}

// AuthorAutoCmd An auto-command to run. Applicable only to session-based shell authorization.
// https://datatracker.ietf.org/doc/html/rfc8907#section-3.7
type AuthorAutoCmd string

// Validate characterics of type based on rfc and usage.
func (t AuthorAutoCmd) Validate(condition interface{}) error {
	// https://datatracker.ietf.org/doc/html/rfc8907#section-3.6
	if isAllASCII(string(t)) {
		return nil
	}
	return fmt.Errorf("AuthorAutoCmd is not all ascii, but it must be, [%v]", t)
}

// Len returns the length of AuthorAutoCmd.
func (t AuthorAutoCmd) Len() int {
	return len(t)
}

// String returns AuthorAutoCmd as a string.
func (t AuthorAutoCmd) String() string {
	return string(t)
}

// AuthorNoEscape Prevents the user from using an escape character. Applicable only to session-based shell authorization.
// https://datatracker.ietf.org/doc/html/rfc8907#section-3.7
type AuthorNoEscape bool

// Validate characterics of type based on rfc and usage.
func (t AuthorNoEscape) Validate(condition interface{}) error {
	return nil
}

// Len returns the length of AuthorNoEscape.
func (t AuthorNoEscape) Len() int {
	return 1
}

// String returns AuthorNoEscape as a string.
func (t AuthorNoEscape) String() string {
	return strconv.FormatBool(bool(t))
}

// AuthorNoHangup Do not disconnect after an automatic command. Applicable only to session-based shell authorization.
// https://datatracker.ietf.org/doc/html/rfc8907#section-3.7
type AuthorNoHangup bool

// Validate characterics of type based on rfc and usage.
func (t AuthorNoHangup) Validate(condition interface{}) error {
	return nil
}

// Len returns the length of AuthorNoHangup.
func (t AuthorNoHangup) Len() int {
	return 1
}

// String returns AuthorNoHangup as a string.
func (t AuthorNoHangup) String() string {
	return strconv.FormatBool(bool(t))
}
