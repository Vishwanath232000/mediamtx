package rtsp

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/bluenviron/gortsplib/v4"
	rtspauth "github.com/bluenviron/gortsplib/v4/pkg/auth"
	"github.com/bluenviron/gortsplib/v4/pkg/base"
	"github.com/google/uuid"

	"github.com/bluenviron/mediamtx/internal/auth"
	"github.com/bluenviron/mediamtx/internal/conf"
	"github.com/bluenviron/mediamtx/internal/defs"
	"github.com/bluenviron/mediamtx/internal/externalcmd"
	"github.com/bluenviron/mediamtx/internal/hooks"
	"github.com/bluenviron/mediamtx/internal/logger"
)

const (
	rtspAuthRealm = "IPCAM"
)

type conn struct {
	isTLS               bool
	rtspAddress         string
	authMethods         []rtspauth.ValidateMethod
	readTimeout         conf.StringDuration
	runOnConnect        string
	runOnConnectRestart bool
	runOnDisconnect     string
	externalCmdPool     *externalcmd.Pool
	pathManager         serverPathManager
	rconn               *gortsplib.ServerConn
	rserver             *gortsplib.Server
	parent              *Server

	uuid             uuid.UUID
	created          time.Time
	onDisconnectHook func()
	authNonce        string
	authFailures     int
}

func (c *conn) initialize() {
	c.Log(logger.Debug, "conn.go > initialize: Begin")
	c.uuid = uuid.New()
	c.created = time.Now()

	c.Log(logger.Info, "opened")

	desc := defs.APIPathSourceOrReader{
		Type: func() string {
			if c.isTLS {
				c.Log(logger.Debug, "conn.go > initialize: End-1")
				return "rtspsConn"
			}
			c.Log(logger.Debug, "conn.go > initialize: End-2")
			return "conn"
		}(),
		ID: c.uuid.String(),
	}

	c.onDisconnectHook = hooks.OnConnect(hooks.OnConnectParams{
		Logger:              c,
		ExternalCmdPool:     c.externalCmdPool,
		RunOnConnect:        c.runOnConnect,
		RunOnConnectRestart: c.runOnConnectRestart,
		RunOnDisconnect:     c.runOnDisconnect,
		RTSPAddress:         c.rtspAddress,
		Desc:                desc,
	})

	c.Log(logger.Debug, "conn.go > initialize: End-99")
}

// Log implements logger.Writer.
func (c *conn) Log(level logger.Level, format string, args ...interface{}) {

	c.parent.Log(level, "[conn %v] "+format, append([]interface{}{c.rconn.NetConn().RemoteAddr()}, args...)...)
}

// Conn returns the RTSP connection.
func (c *conn) Conn() *gortsplib.ServerConn {

	return c.rconn
}

func (c *conn) remoteAddr() net.Addr {

	return c.rconn.NetConn().RemoteAddr()
}

func (c *conn) ip() net.IP {
	return c.rconn.NetConn().RemoteAddr().(*net.TCPAddr).IP
}

// onClose is called by rtspServer.
func (c *conn) onClose(err error) {
	c.Log(logger.Debug, "conn.go > onClose: Begin")
	c.Log(logger.Info, "closed: %v", err)

	c.onDisconnectHook()
	c.Log(logger.Debug, "conn.go > onClose: End-99")
}

// onRequest is called by rtspServer.
func (c *conn) onRequest(req *base.Request) {
	c.Log(logger.Debug, "conn.go > onRequest: Begin")
	c.Log(logger.Debug, "[c->s] %v", req)
	c.Log(logger.Debug, "conn.go > onRequest: End-99")
}

// OnResponse is called by rtspServer.
func (c *conn) OnResponse(res *base.Response) {
	c.Log(logger.Debug, "conn.go > OnResponse: Begin")
	c.Log(logger.Debug, "[s->c] %v", res)
	c.Log(logger.Debug, "conn.go > OnResponse: End-99")
}

// onDescribe is called by rtspServer.
func (c *conn) onDescribe(ctx *gortsplib.ServerHandlerOnDescribeCtx,
) (*base.Response, *gortsplib.ServerStream, error) {
	c.Log(logger.Debug, "conn.go > onDescribe: Begin")
	if len(ctx.Path) == 0 || ctx.Path[0] != '/' {
		c.Log(logger.Debug, "conn.go > onDescribe: End-1")
		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, nil, fmt.Errorf("invalid path")
	}
	ctx.Path = ctx.Path[1:]

	if c.authNonce == "" {
		var err error
		c.authNonce, err = rtspauth.GenerateNonce()
		if err != nil {
			c.Log(logger.Debug, "conn.go > onDescribe: End-2")
			return &base.Response{
				StatusCode: base.StatusInternalServerError,
			}, nil, err
		}
	}

	res := c.pathManager.Describe(defs.PathDescribeReq{
		AccessRequest: defs.PathAccessRequest{
			Name:        ctx.Path,
			Query:       ctx.Query,
			IP:          c.ip(),
			Proto:       auth.ProtocolRTSP,
			ID:          &c.uuid,
			RTSPRequest: ctx.Request,
			RTSPNonce:   c.authNonce,
		},
	})

	if res.Err != nil {
		var terr *auth.Error
		if errors.As(res.Err, &terr) {
			res, err := c.handleAuthError(terr)
			c.Log(logger.Debug, "conn.go > onDescribe: End-3")
			return res, nil, err
		}

		var terr2 defs.PathNoOnePublishingError
		if errors.As(res.Err, &terr2) {
			c.Log(logger.Debug, "conn.go > onDescribe: End-4")
			return &base.Response{
				StatusCode: base.StatusNotFound,
			}, nil, res.Err
		}

		c.Log(logger.Debug, "conn.go > onDescribe: End-5")

		return &base.Response{
			StatusCode: base.StatusBadRequest,
		}, nil, res.Err
	}

	if res.Redirect != "" {
		c.Log(logger.Debug, "conn.go > onDescribe: End-6")
		return &base.Response{
			StatusCode: base.StatusMovedPermanently,
			Header: base.Header{
				"Location": base.HeaderValue{res.Redirect},
			},
		}, nil, nil
	}

	var stream *gortsplib.ServerStream
	if !c.isTLS {
		stream = res.Stream.RTSPStream(c.rserver)
	} else {
		stream = res.Stream.RTSPSStream(c.rserver)
	}

	c.Log(logger.Debug, "conn.go > onDescribe: End-99")

	return &base.Response{
		StatusCode: base.StatusOK,
	}, stream, nil
}

func (c *conn) handleAuthError(authErr error) (*base.Response, error) {
	c.Log(logger.Debug, "conn.go > handleAuthError: Begin")
	c.authFailures++

	// VLC with login prompt sends 4 requests:
	// 1) without credentials
	// 2) with password but without username
	// 3) without credentials
	// 4) with password and username
	// therefore we must allow up to 3 failures
	if c.authFailures <= 3 {
		c.Log(logger.Debug, "conn.go > handleAuthError: End-1")
		return &base.Response{
			StatusCode: base.StatusUnauthorized,
			Header: base.Header{
				"WWW-Authenticate": rtspauth.GenerateWWWAuthenticate(c.authMethods, rtspAuthRealm, c.authNonce),
			},
		}, nil
	}

	// wait some seconds to mitigate brute force attacks
	<-time.After(auth.PauseAfterError)
	c.Log(logger.Debug, "conn.go > handleAuthError: End-99")

	return &base.Response{
		StatusCode: base.StatusUnauthorized,
	}, authErr
}

func (c *conn) apiItem() *defs.APIRTSPConn {

	return &defs.APIRTSPConn{
		ID:            c.uuid,
		Created:       c.created,
		RemoteAddr:    c.remoteAddr().String(),
		BytesReceived: c.rconn.BytesReceived(),
		BytesSent:     c.rconn.BytesSent(),
	}
}
