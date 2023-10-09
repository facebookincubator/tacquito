/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"fmt"
	"unicode"
)

const (
	// MaxBodyLength is the total length of the packet body (not including the header).
	// Implementations MUST allow control over maximum packet sizes
	// accepted by TACACS+ Servers.  The recommended maximum packet size
	// is 2^(16).
	MaxBodyLength uint32 = 65536
)

// EncoderDecoder will encode or decode from wire format, any of the tacacs packet types
type EncoderDecoder interface {
	MarshalBinary() ([]byte, error)
	UnmarshalBinary(data []byte) error
	Fields() map[string]string
}

// Unmarshal will unmarshal tacacs bytes
func Unmarshal(v []byte, t EncoderDecoder) error {
	if t == nil {
		return fmt.Errorf("unmarshal cannot decode")
	}
	return t.UnmarshalBinary(v)
}

// PacketOption is used to inject options when creating new Packet types
type PacketOption func(*Packet)

// SetPacketHeader sets the header
func SetPacketHeader(v *Header) PacketOption {
	return func(p *Packet) {
		p.Header = v
	}
}

// SetPacketBody sets the body of packet
func SetPacketBody(v []byte) PacketOption {
	return func(p *Packet) {
		if p.Header != nil {
			p.Header.Length = uint32(len(v))
		}
		p.Body = v
	}
}

// SetPacketBodyUnsafe sets the body of packet by calling MarshalBinary on v.
// errors trigger a panic.  this setter is ONLY meant for testing scenarios
// if you use this in production handler code you're asking for panics to kill
// your service.
func SetPacketBodyUnsafe(v EncoderDecoder) PacketOption {
	return func(p *Packet) {
		b, err := v.MarshalBinary()
		if err != nil {
			panic(fmt.Errorf("error in SetPacketBodyUnsafe, this should not be used in a service.  %v", err))
		}
		if p.Header != nil {
			p.Header.Length = uint32(len(b))
		}
		p.Body = b
	}
}

// NewPacket will create a new Packet based on the provided options.
func NewPacket(opts ...PacketOption) *Packet {
	p := &Packet{}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Packet is used as a request and response packet.
// Header is the decoded header fields from the tacacs packet
// RawBody may be obfuscated or deobfuscated, depending on where the packet is in the req/resp flow
// Body will always be a decoded type, eg AuthenStart, AuthenReply, AcctRequest, etc.
type Packet struct {
	// Header is a well known structure, so it's always populated.  it's also the only
	// part of a tacacs message that isn't crypted, so it can be freely read.
	Header *Header
	// Body may be crypted or uncrypted bytes of the body, length indicated in the header.Length
	Body []byte
}

// MarshalBinary encodes Packet into tacacs bytes. It is unaware of crypt.
// RawBody must have valid values
func (p *Packet) MarshalBinary() ([]byte, error) {
	if p.Header == nil {
		return nil, fmt.Errorf("header is nil, cannot MarshalBinary")
	}
	if p.Body == nil {
		return nil, fmt.Errorf("body is nil, cannot MarshalBinary")
	}
	if p.Header.Length > MaxBodyLength {
		return nil, fmt.Errorf("indicated size is too large to marshal; max allowed [%v] reported [%v]", MaxBodyLength, p.Header.Length)
	}
	head, err := p.Header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	buf := make([]byte, 0, len(head)+len(p.Body))
	buf = append(buf, head...)
	buf = append(buf, p.Body...)
	return buf, nil
}

// UnmarshalBinary decodes Packet into tacacs bytes. It is unaware of crypt.
func (p *Packet) UnmarshalBinary(v []byte) error {
	if v == nil {
		return fmt.Errorf("cannot unmarshal a nil slice")
	}
	// Unmarshal failure will lead to the connection being closed
	var err error
	var h Header
	if len(v) < MaxHeaderLength {
		return fmt.Errorf("data length [%v] is smaller than expected header length [%v]", len(v), MaxHeaderLength)
	}
	err = Unmarshal(v[:MaxHeaderLength], &h)
	if err != nil {
		return fmt.Errorf("failed header unmarshal: [%w]", err)
	}
	p.Header = &h
	if h.Length > MaxBodyLength {
		return fmt.Errorf("indicated size is too large to unmarshal; max allowed [%v] reported [%v]", MaxBodyLength, h.Length)
	}
	p.Body = v[MaxHeaderLength : MaxHeaderLength+int(h.Length)]
	return nil
}

// Fields returns fields from this packet compatible with a structured logger
func (p *Packet) Fields() map[string]string {
	return nil
}

// Field is a tacacs field interface used across all three AAA types.
type Field interface {
	// Validate is executed on all MarshalBinary and UnmarshalBinary operations on
	// Authenticate, Authorize and Accounting Packet types
	Validate(condition interface{}) error

	// Len of Field value
	Len() int

	// String representation for printing. Obscure operations also happen here
	String() string
}

// readBuffer is used during the UnmarshallBinary operation.
// each call to any of readBuffer's methods will mutate the contents
// of b
type readBuffer []byte

// int returns a single byte as an int
func (b *readBuffer) int() int {
	return int(b.byte())
}

// byte returns one byte from b
func (b *readBuffer) byte() byte {
	s := (*b)
	if len(s) < 1 {
		return uint8(0)
	}
	c := s[0]
	*b = s[1:]
	return c
}

// uint16 extracts a uint16 from b and returns it as an int
// if only one byte is available, we just return that value
func (b *readBuffer) uint16() int {
	s := (*b)
	if len(s) == 1 {
		return b.int()
	}
	if len(s) >= 2 {
		n := int(s[0])<<8 | int(s[1])
		*b = s[2:]
		return n
	}
	return 0
}

// string will convert the bytes indicated by n to a string
// if n is larger than b, it is reduced to match
func (b *readBuffer) string(n int) string {
	s := (*b)
	if len(s) < 1 {
		return ""
	}
	if len(s) < n {
		n = len(s)
	}
	str := s[:n]
	*b = s[n:]
	return string(str)
}

// appendUint16 will append an int to a []byte as a uint16 but shifting bits
func appendUint16(b []byte, i int) []byte {
	return append(b, byte(i>>8), byte(i))
}

// isAllASCII will ensure that the given string only uses ascii characters.
// it will return false if it has anything other than ascii, true, if it's safe ascii.
func isAllASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > unicode.MaxASCII {
			return false
		}
	}
	return true
}
