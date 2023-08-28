/*
 Copyright (c) Facebook, Inc. and its affiliates.

 This source code is licensed under the MIT license found in the
 LICENSE file in the root directory of this source tree.
*/

package tacquito

import (
	"context"
)

// Writer is an abstraction used for adding Writers to the response object
type Writer interface {
	Write(ctx context.Context, p []byte) (int, error)
}

// response implements the Response interface.  when testing handlers, provide your own
// mock of this struct via the interface. crypt operations are not exposed for testing.
type response struct {
	loggerProvider
	ctx     context.Context
	crypter *crypter
	next    Handler
	// header is the corresponding header that was used to create this response
	header Header
	// slice of writers to write back the response
	writers []Writer
}

// Reply will write the provided EncoderDecoder to the underlying net.Conn.  This method handles
// all header values based on the underlying EncoderDecoder.  If you want total control on the
// packet that is written, use Send instead.
func (r *response) Reply(v EncoderDecoder) (int, error) {
	seqNo := int(r.header.SeqNo)
	// some special conditions for different body types
	switch t := v.(type) {
	case *AuthenReply:
		if t.Status == AuthenStatusRestart {
			seqNo = 1
		} else {
			seqNo++
		}
	default:
		seqNo++
	}
	header := NewHeader(
		SetHeaderVersion(r.header.Version),
		SetHeaderType(r.header.Type),
		SetHeaderSeqNo(seqNo),
		SetHeaderFlag(r.header.Flags),
		SetHeaderSessionID(r.header.SessionID),
	)
	b, err := v.MarshalBinary()
	if err != nil {
		r.Errorf(r.ctx, "unable to marshal packet; %v", err)
		return 0, err
	}
	r.header = *header
	p := NewPacket(
		SetPacketHeader(header),
		SetPacketBody(b),
	)
	if pbytes, err := p.MarshalBinary(); err == nil {
		for _, mw := range r.writers {
			_, err := mw.Write(r.ctx, pbytes)
			if err != nil {
				r.Errorf(r.ctx, "unable to write to response writer; %v", err)
			}
		}
	}
	return r.Write(p)
}

// Write will write the packet to the underlying net.Conn.  If you are expecting another packet
// to return from the client after writing a response, call Next(handler) to provide a next Handler.
func (r *response) Write(p *Packet) (int, error) {
	return r.crypter.write(p)
}

// Next sets the incoming handler to next. This is only used for exchange sequences within the authenticate
// packet types
func (r *response) Next(next Handler) {
	r.next = next
}

func (r *response) RegisterWriter(mw Writer) {
	r.writers = append(r.writers, mw)
}

func (r *response) Context(ctx context.Context) {
	r.ctx = ctx
}

// ReplyWithContext can be used to reply to requests that cause a server error or failure in processing of response.
// This method includes an additional variadic argument `writers` that can be used to write the response `v` to
// other sinks (eg logging backends)
// This method also overwrites the response's context with the supplied `ctx`
func (r *response) ReplyWithContext(ctx context.Context, v EncoderDecoder, writers ...Writer) (int, error) {
	r.Context(ctx)
	for _, w := range writers {
		if w != nil {
			r.RegisterWriter(w)
		}
	}
	return r.Reply(v)
}

// Response controls what we send back to the client.  Calls to Write should be considered final on the
// packet back to the client.  You may not call Exchange after Write.
type Response interface {
	Reply(v EncoderDecoder) (int, error)
	ReplyWithContext(ctx context.Context, v EncoderDecoder, writers ...Writer) (int, error)
	Write(p *Packet) (int, error)
	Next(next Handler)
	RegisterWriter(Writer)
	// Context sets context of response to ctx
	Context(ctx context.Context)
}

// Request provides access to the config for this net.Conn and also the packet itself
type Request struct {
	Header  Header
	Body    []byte
	Context context.Context
}

// Fields will extract all fields from any packet type and attempt to include any optional
// ContextKey values
func (r Request) Fields(keys ...ContextKey) map[string]string {
	allFields := r.Header.Fields()

	// add optional context values
	if r.Context != nil {
		for _, key := range keys {
			v, ok := r.Context.Value(key).(string)
			if ok {
				allFields[string(key)] = v
			}
		}
	}

	// merge will add our header fields to the body
	// the rfc doesn't contain fields that collide
	merge := func(a, b map[string]string) {
		for k, v := range b {
			a[k] = v
		}
	}
	switch r.Header.Type {
	case Authenticate:
		var as AuthenStart
		if err := Unmarshal(r.Body, &as); err == nil {
			merge(allFields, as.Fields())
			return allFields
		}
		var ac AuthenContinue
		if err := Unmarshal(r.Body, &ac); err == nil {
			merge(allFields, ac.Fields())
			return allFields
		}
		var ar AuthenReply
		if err := Unmarshal(r.Body, &ar); err == nil {
			merge(allFields, ar.Fields())
			return allFields
		}

	case Authorize:
		var ar AuthorRequest
		if err := Unmarshal(r.Body, &ar); err == nil {
			merge(allFields, ar.Fields())
			return allFields
		}
		var arr AuthorReply
		if err := Unmarshal(r.Body, &arr); err == nil {
			merge(allFields, arr.Fields())
			return allFields
		}

	case Accounting:
		var ar AcctRequest
		if err := Unmarshal(r.Body, &ar); err == nil {
			merge(allFields, ar.Fields())
			return allFields
		}
		var arr AcctReply
		if err := Unmarshal(r.Body, &arr); err == nil {
			merge(allFields, arr.Fields())
			return allFields
		}
	}
	// unknown packet
	return nil
}

// Handler form the basis for the state machine during client server exchanges.
type Handler interface {
	Handle(response Response, request Request)
}

// HandlerFunc is an adapter that allows higher order functions to be used as Handler interfaces
type HandlerFunc func(response Response, request Request)

// Handle satisfies the Handler interface
func (h HandlerFunc) Handle(response Response, request Request) {
	h(response, request)
}
