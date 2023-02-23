package test

import (
	"context"
	"io"
	"testing"

	tq "github.com/facebookincubator/tacquito"
	"github.com/facebookincubator/tacquito/cmds/server/handlers"
	"github.com/facebookincubator/tacquito/cmds/server/log"

	"github.com/stretchr/testify/assert"
)

type MockHandler struct{}

func (m MockHandler) Handle(response tq.Response, request tq.Request) {}

func BenchmarkAuthenLogger(b *testing.B) {
	header := tq.NewHeader(
		tq.SetHeaderVersion(tq.Version{MajorVersion: tq.MajorVersion, MinorVersion: tq.MinorVersionDefault}),
		tq.SetHeaderType(tq.Authenticate),
		tq.SetHeaderSessionID(12345),
	)
	as := tq.NewAuthenStart(
		tq.SetAuthenStartAction(tq.AuthenActionLogin),
		tq.SetAuthenStartPrivLvl(tq.PrivLvlUser),
		tq.SetAuthenStartType(tq.AuthenTypeASCII),
		tq.SetAuthenStartService(tq.AuthenServiceLogin),
		tq.SetAuthenStartPort("tty0"),
		tq.SetAuthenStartRemAddr("foo"),
	)
	body, err := as.MarshalBinary()
	assert.NoError(b, err)
	ctx := context.Background()
	req := tq.Request{
		Header:  *header,
		Body:    body,
		Context: ctx,
	}
	logger := log.New(30, io.Discard)
	al := handlers.NewCtxLogger(
		logger,
		req,
		MockHandler{},
	)
	for n := 0; n < b.N; n++ {
		al.Gather()
	}

}
