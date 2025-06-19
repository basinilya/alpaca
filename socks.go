package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"bufio"
	"io"

	go_net "net"
	"net/http"
	"net/url"

	"strconv"

	"v2ray.com/core"

	app_policy "v2ray.com/core/app/policy"
	"v2ray.com/core/common/buf"
	"v2ray.com/core/common/net"
	"v2ray.com/core/common/session"
	"v2ray.com/core/proxy/socks"
	v_transport "v2ray.com/core/transport"
)

func ServerType() interface{} {
	return (*AlpacaVDispatcher)(nil)
}

func startSocks5ListenerWithHandler(httpHandler http.Handler) error {

	serverConfig := socks.ServerConfig{
		AuthType:  socks.AuthType_NO_AUTH,
		UserLevel: 1,
	}
	debugTimeouts := &app_policy.Policy_Timeout{
		Handshake:      &app_policy.Second{Value: 199},
		ConnectionIdle: &app_policy.Second{Value: 19},
		UplinkOnly:     &app_policy.Second{Value: 18},
		DownlinkOnly:   &app_policy.Second{Value: 17},
	}
	debugAppPolicyConfig := &app_policy.Policy{Timeout: debugTimeouts}
	debugPolicyLevel := map[uint32]*app_policy.Policy{1: debugAppPolicyConfig}
	policyConfig := &app_policy.Config{Level: debugPolicyLevel}
	dummyManager, _ := app_policy.New(context.TODO(), policyConfig)
	dummyV := core.Instance{}
	dummyV.AddFeature(dummyManager)
	tmp, err := core.CreateObject(&dummyV, &serverConfig)
	if err != nil {
		return err
	}
	socksServer := tmp.(*socks.Server)

	ln, err := net.Listen("tcp", ":1080")
	if err != nil {
		return err
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				continue
			}
			// Pass conn to SOCKS5 protocol handler
			go func() {
				handleV2RaySocksConn(conn, httpHandler, socksServer)
			}()
		}
	}()

	return nil
}

type key int

const v2raykey key = 1

func handleV2RaySocksConn(conn net.Conn, handler http.Handler, socksServer *socks.Server) {
	var err error
	defer conn.Close()
	ctx := context.Background()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		Gateway: net.TCPDestination(net.AnyIP, 0),
	})

	dispatcher := &AlpacaVDispatcher{handler}

	// This will parse the handshake and call
	// dispatcher.Dispatch() then copy the data in both directions
	err = socksServer.Process(ctx, net.Network_TCP, conn, dispatcher)
	if err != nil {
		log.Printf("SOCKS Process failed: %v", err)
		return
	}
}

type AlpacaVDispatcher struct {
	handler http.Handler
}

func (d *AlpacaVDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*v_transport.Link, error) {
	var err error

	targetAddr := dest.NetAddr()

	// Build a fake HTTP CONNECT request
	fakeReq := &http.Request{
		Method: "CONNECT",
		URL: &url.URL{
			Scheme: "https",
			Host:   targetAddr,
		},
		Host:       targetAddr,
		Header:     make(http.Header),
		Body:       http.NoBody,
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	fakeReq = fakeReq.WithContext(ctx)

	reqPipeRd, reqPipeWr := io.Pipe()
	resPipeRd, resPipeWr := io.Pipe()

	conn := NewHTTPFilteringConn(reqPipeRd, resPipeWr)
	rw := &dummyResponseWriter{req: fakeReq, conn: conn}

	// Call Alpaca’s handler in background
	go d.handler.ServeHTTP(rw, fakeReq)
	statusOk, err := conn.WaitReady(ctx)
	if err != nil {
		reqPipeRd.Close()
		resPipeRd.Close()
		return nil, err
	}
	if !statusOk {
		reqPipeRd.Close()
		resPipeRd.Close()
		return nil, fmt.Errorf("failed to connect to upstream proxy")
	}

	link := &v_transport.Link{
		Reader: buf.NewReader(resPipeRd), // response
		Writer: buf.NewWriter(reqPipeWr), // request
	}

	return link, nil
}

func (d *AlpacaVDispatcher) Close() error {
	// no-op
	return nil
}

func (d *AlpacaVDispatcher) Start() error {
	panic("unimplemented")
}

func (d *AlpacaVDispatcher) Type() interface{} {
	return ServerType()
}

type HTTPFilteringConn struct {
	reqPipeRd *io.PipeReader
	resPipeWr *io.PipeWriter

	headerBuf  bytes.Buffer
	headerDone bool
	statusOK   bool
	headerErr  error

	readyCh chan struct{} // closed when headerDone is set
}

func NewHTTPFilteringConn(reqPipeRd *io.PipeReader, resPipeWr *io.PipeWriter) *HTTPFilteringConn {
	return &HTTPFilteringConn{
		reqPipeRd: reqPipeRd,
		resPipeWr: resPipeWr,
		readyCh:   make(chan struct{}),
	}
}

func (d *HTTPFilteringConn) WaitReady(ctx context.Context) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-d.readyCh:
		return d.statusOK, d.headerErr
	}
}

func (d *HTTPFilteringConn) Write(b []byte) (int, error) {
	if d.headerDone {
		if !d.statusOK {
			return len(b), nil // Discard
		}
		return d.resPipeWr.Write(b)
	}

	_, err := d.headerBuf.Write(b)
	if err != nil {
		d.markReady(false, err)
		return 0, err
	}

	bufReader := bufio.NewReader(&d.headerBuf)
	resp, err := http.ReadResponse(bufReader, nil)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return len(b), nil // Not enough data yet
		}
		d.markReady(false, fmt.Errorf("failed to parse HTTP response: %w", err))
		return 0, err
	}

	ok := resp.StatusCode == http.StatusOK
	rest, err := io.ReadAll(bufReader)
	if err != nil {
		d.markReady(false, fmt.Errorf("reading body after header failed: %w", err))
		return 0, err
	}

	d.markReady(ok, nil)

	if ok {
		_, err = d.resPipeWr.Write(rest)
		if err != nil {
			return 0, err
		}
	}

	d.headerBuf.Reset()
	return len(b), nil
}

func (d *HTTPFilteringConn) markReady(ok bool, err error) {
	if !d.headerDone {
		d.headerDone = true
		d.statusOK = ok
		d.headerErr = err
		close(d.readyCh)
	}
}

// Close implements net.Conn.
func (d *HTTPFilteringConn) Close() error {
	d.reqPipeRd.Close()
	d.resPipeWr.Close()
	return nil
}

// Read implements net.Conn.
func (d *HTTPFilteringConn) Read(b []byte) (n int, err error) {
	return d.reqPipeRd.Read(b)
}

// LocalAddr implements net.Conn.
func (d *HTTPFilteringConn) LocalAddr() go_net.Addr {
	panic("unimplemented")
}

// RemoteAddr implements net.Conn.
func (d *HTTPFilteringConn) RemoteAddr() go_net.Addr {
	panic("unimplemented")
}

// SetDeadline implements net.Conn.
func (d *HTTPFilteringConn) SetDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetReadDeadline implements net.Conn.
func (d *HTTPFilteringConn) SetReadDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetWriteDeadline implements net.Conn.
func (d *HTTPFilteringConn) SetWriteDeadline(t time.Time) error {
	panic("unimplemented")
}

type dummyResponseWriter struct {
	req  *http.Request
	conn net.Conn
}

func (w *dummyResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, nil, nil
}

func (w *dummyResponseWriter) Header() http.Header {
	return http.Header{}
}

func (w *dummyResponseWriter) Write(p []byte) (int, error) {
	return w.conn.Write(p)
}

func (w *dummyResponseWriter) WriteHeader(statusCode int) {
	var pref string
	if w.req.ProtoAtLeast(1, 1) {
		pref = "HTTP/1.1 "
	} else {
		pref = "HTTP/1.0 "
	}

	if statusCode == http.StatusOK {
		w.conn.Write([]byte(pref + strconv.Itoa(statusCode) + " Dummy Phrase\r\n\r\n"))
	}
}
