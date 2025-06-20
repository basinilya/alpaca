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
		ConnectionIdle: &app_policy.Second{Value: 119},
		UplinkOnly:     &app_policy.Second{Value: 118},
		DownlinkOnly:   &app_policy.Second{Value: 117},
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

	var reqPipeRd io.ReadCloser
	var reqPipeWr io.WriteCloser
	var resPipeRd io.ReadCloser
	var resPipeWr io.WriteCloser

	reqPipeRd, reqPipeWr = io.Pipe()
	resPipeRd, resPipeWr = io.Pipe()

	reqPipeRd, reqPipeWr = LoggingPipeWrap("req", reqPipeRd, reqPipeWr)
	resPipeRd, resPipeWr = LoggingPipeWrap("res", resPipeRd, resPipeWr)

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

	// The Writer returned by Dispatch() is expected to implement Close().
	// After one request the upstream server is likely to keep the connection open.
	// Close() helps to detect the disconnected downstream
	linkReader := struct {
		io.ReadCloser
		buf.Reader
	}{ReadCloser: resPipeRd, Reader: buf.NewReader(resPipeRd)}

	linkWriter := struct {
		io.WriteCloser
		buf.Writer
	}{WriteCloser: reqPipeWr, Writer: buf.NewWriter(reqPipeWr)}

	link := &v_transport.Link{
		Reader: linkReader, // response
		Writer: linkWriter, // request
	}

	return link, nil
}

func LoggingPipeWrap(id string, r io.ReadCloser, w io.WriteCloser) (io.ReadCloser, io.WriteCloser) {
	return &loggingPipeReader{ReadCloser: r, id: id}, &loggingPipeWriter{WriteCloser: w, id: id}
}

type loggingPipeReader struct {
	io.ReadCloser
	id string // optional: tag for logging
}

func (r *loggingPipeReader) Close() error {
	log.Printf("PipeReader %s closing", r.id)
	return r.ReadCloser.Close()
}

type loggingPipeWriter struct {
	io.WriteCloser
	id string
}

func (w *loggingPipeWriter) Close() error {
	log.Printf("PipeWriter %s closing", w.id)
	return w.WriteCloser.Close()
}

func (d *AlpacaVDispatcher) Close() error {
	// no-op
	log.Printf("Closing Dispatcher")
	return nil
}

func (d *AlpacaVDispatcher) Start() error {
	panic("unimplemented")
}

func (d *AlpacaVDispatcher) Type() interface{} {
	return ServerType()
}

type HTTPFilteringConn struct {
	reqPipeRd io.ReadCloser
	resPipeWr io.WriteCloser

	headerBuf  bytes.Buffer
	headerDone bool
	statusOK   bool
	headerErr  error

	readyCh chan struct{} // closed when headerDone is set
}

func NewHTTPFilteringConn(reqPipeRd io.ReadCloser, resPipeWr io.WriteCloser) *HTTPFilteringConn {
	return &HTTPFilteringConn{
		reqPipeRd: reqPipeRd,
		resPipeWr: resPipeWr,
		readyCh:   make(chan struct{}),
	}
}

func (c *HTTPFilteringConn) WaitReady(ctx context.Context) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-c.readyCh:
		return c.statusOK, c.headerErr
	}
}

func (c *HTTPFilteringConn) Write(b []byte) (int, error) {
	if c.headerDone {
		if !c.statusOK {
			return len(b), nil // Discard
		}
		return c.resPipeWr.Write(b)
	}

	_, err := c.headerBuf.Write(b)
	if err != nil {
		c.markReady(false, err)
		return 0, err
	}

	bufReader := bufio.NewReader(&c.headerBuf)
	resp, err := http.ReadResponse(bufReader, nil)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return len(b), nil // Not enough data yet
		}
		c.markReady(false, fmt.Errorf("failed to parse HTTP response: %w", err))
		return 0, err
	}

	ok := resp.StatusCode == http.StatusOK
	rest, err := io.ReadAll(bufReader)
	if err != nil {
		c.markReady(false, fmt.Errorf("reading body after header failed: %w", err))
		return 0, err
	}

	c.markReady(ok, nil)

	if ok {
		_, err = c.resPipeWr.Write(rest)
		if err != nil {
			return 0, err
		}
	}

	c.headerBuf.Reset()
	return len(b), nil
}

func (c *HTTPFilteringConn) markReady(ok bool, err error) {
	if !c.headerDone {
		c.headerDone = true
		c.statusOK = ok
		c.headerErr = err
		close(c.readyCh)
	}
}

// Close implements net.Conn.
func (c *HTTPFilteringConn) Close() error {
	log.Printf("Closing HTTPFilteringConn")
	c.reqPipeRd.Close()
	c.resPipeWr.Close()
	return nil
}

func (c *HTTPFilteringConn) CloseWrite() error {
	return c.resPipeWr.Close()
}

// Read implements net.Conn.
func (c *HTTPFilteringConn) Read(b []byte) (n int, err error) {
	return c.reqPipeRd.Read(b)
}

// LocalAddr implements net.Conn.
func (c *HTTPFilteringConn) LocalAddr() go_net.Addr {
	panic("unimplemented")
}

// RemoteAddr implements net.Conn.
func (c *HTTPFilteringConn) RemoteAddr() go_net.Addr {
	panic("unimplemented")
}

// SetDeadline implements net.Conn.
func (c *HTTPFilteringConn) SetDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetReadDeadline implements net.Conn.
func (c *HTTPFilteringConn) SetReadDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetWriteDeadline implements net.Conn.
func (c *HTTPFilteringConn) SetWriteDeadline(t time.Time) error {
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

	w.conn.Write([]byte(pref + strconv.Itoa(statusCode) + " Dummy Phrase\r\n\r\n"))
}
