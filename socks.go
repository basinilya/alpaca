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
	"v2ray.com/core/common/protocol"
	"v2ray.com/core/common/session"
	"v2ray.com/core/proxy/socks"
	v_transport "v2ray.com/core/transport"
)

// called from connectViaProxy
func connectViaSocks(id any, proxyHostAndPort string, destHostAndPort string) (net.Conn, error) {
	var err error
	dest, err := net.ParseDestination(destHostAndPort)
	if err != nil {
		log.Printf("[%d] Invalid destination %s: %v", id, destHostAndPort, err)
		return nil, err
	}

	closeInDefer := true

	conn, err := net.Dial("tcp", proxyHostAndPort)
	if err != nil {
		log.Printf("[%d] Error dialling socks %s: %v", id, proxyHostAndPort, err)
		return nil, err
	}

	defer func() {
		if closeInDefer {
			conn.Close()
		}
	}()

	request := &protocol.RequestHeader{
		Version: 5,
		Command: protocol.RequestCommandTCP,
		Address: dest.Address,
		Port:    dest.Port,
	}

	_, err = socks.ClientHandshake(request, conn, conn)
	if err != nil {
		log.Printf("[%d] socks handshake failed: %v", id, err)
		return nil, err
	}

	closeInDefer = false
	return conn, nil
}

// called from main
func startSocks5ListenerWithHandler(httpHandler http.Handler, listenhostandport string) error {
	socksServer, err := createSocksServer()
	if err != nil {
		return err
	}

	host, port, err1 := go_net.SplitHostPort(listenhostandport)
	if err1 != nil {
		tmp := go_net.JoinHostPort(listenhostandport, "1080")
		host, port, err1 = go_net.SplitHostPort(tmp)
		if err1 != nil {
			log.Printf("SOCKS failed to parse %s: %s", listenhostandport, err)
			return err1
		}
		listenhostandport = tmp
	} else if port == "" {
		port = "1080"
		listenhostandport = go_net.JoinHostPort(host, port)
	}

	// LookupIP may return duplicates
	uniqueIPs := make(map[string]struct{})
	listenerCount := 0
	var lasterr error

	startAcceptLoop := func(ipport string) {
		if _, seen := uniqueIPs[ipport]; seen {
			return
		}
		uniqueIPs[ipport] = struct{}{}
		ln, err := net.Listen("tcp", ipport)
		if err != nil {
			lasterr = err
		} else {
			sLnAddr := ln.Addr()
			listenerCount++
			log.Printf("SOCKS listening on %s", sLnAddr)
			go func() {
				defer ln.Close()
				for {
					conn, err := ln.Accept()
					if err != nil {
						log.Printf("SOCKS failed to accept on %s: %s", sLnAddr, err)
						break
					}
					log.Printf("SOCKS accepted: %s -> %s", conn.RemoteAddr(), conn.LocalAddr())
					conn2 := conn.(*net.TCPConn)
					// Pass conn to SOCKS5 protocol handler
					go func() {
						handleV2RaySocksConn(conn2, httpHandler, socksServer)
					}()
				}
			}()
		}
	}

	if host != "" {
		unsortedips, err := net.LookupIP(host)
		if err != nil {
			log.Printf("SOCKS failed to resolve %s: %s", host, err)
			return err
		}
		for _, ip := range unsortedips {
			ipport := go_net.JoinHostPort(ip.String(), port)
			startAcceptLoop(ipport)
		}
	} else {
		startAcceptLoop(listenhostandport)
	}

	if listenerCount == 0 {
		log.Printf("SOCKS failed to listen on %s: %s", listenhostandport, lasterr)
		return lasterr
	}

	return nil
}

func createSocksServer() (*socks.Server, error) {
	serverConfig := socks.ServerConfig{
		AuthType:  socks.AuthType_NO_AUTH,
		UserLevel: 1,
	}
	// default was 1 second
	timeouts := &app_policy.Policy_Timeout{
		Handshake:    &app_policy.Second{Value: 20},
		UplinkOnly:   &app_policy.Second{Value: 20},
		DownlinkOnly: &app_policy.Second{Value: 20},
	}
	appPolicyConfig := &app_policy.Policy{Timeout: timeouts}
	policyLevel := map[uint32]*app_policy.Policy{1: appPolicyConfig}
	policyConfig := &app_policy.Config{Level: policyLevel}
	dummyManager, _ := app_policy.New(context.TODO(), policyConfig)
	dummyV := core.Instance{}
	dummyV.AddFeature(dummyManager)
	tmp, err := core.CreateObject(&dummyV, &serverConfig)
	if err != nil {
		log.Printf("SOCKS failed to instantiate Server object: %s", err)
		return nil, err
	}
	socksServer := tmp.(*socks.Server)
	return socksServer, nil
}

func handleV2RaySocksConn(conn *net.TCPConn, handler http.Handler, socksServer *socks.Server) {
	var err error
	defer conn.Close()
	ctx := context.Background()
	ctx = session.ContextWithInbound(ctx, &session.Inbound{
		// This field is used by UDP but V2Ray checks its presence unconditionally
		Gateway: net.TCPDestination(net.AnyIP, 0),
	})

	conn2 := &handshakeConn{TCPConn: conn}
	dispatcher := &alpacaVDispatcher{handler, conn2}

	// This will parse the handshake and call
	// dispatcher.Dispatch() then copy the data in both directions
	err = socksServer.Process(ctx, net.Network_TCP, conn2, dispatcher)
	if err != nil {
		log.Printf("SOCKS Process failed: %v", err)
		return
	}
}

// Wrapper that delays the socks granted response until Dispatch() returns a
// connected Link because V2Ray 4.19.1 writes this response immediately causing
// false success
type handshakeConn struct {
	*net.TCPConn
	state     int
	headerBuf bytes.Buffer
}

const (
	handshakePassRequested = 3
	handshakeAuthenticated = 6
	handshakeGranted       = 9
	handshakeEnded         = 10
)

func (c *handshakeConn) Read(b []byte) (int, error) {
	if c.headerBuf.Len() > 0 && len(b) > 0 {
		// unexpected read
		c.flushHandshake(handshakeEnded)
	}
	return c.TCPConn.Read(b)
}

func (c *handshakeConn) Write(b []byte) (n int, err error) {
	if c.state == handshakeEnded {
		return c.TCPConn.Write(b)
	}

	var n2 int
	var b2 []byte
	n, err = c.headerBuf.Write(b)
	if err != nil || c.headerBuf.Len() < 2 {
		return n, err
	}
	b2 = c.headerBuf.Bytes()

	newstate := handshakeEnded
	if c.state == 0 {
		if b2[0] == 0x00 {
			// v4
			if b2[1] == 90 {
				// granted, will flush later
				c.state = handshakeGranted
				return n, err
			}
		} else if b2[0] == 5 {
			// v5
			if b2[1] == 0 {
				// authNotRequired
				newstate = handshakeAuthenticated
			} else if b2[1] != 0xFF {
				// password
				newstate = handshakePassRequested
			}
		}
	} else if c.state == handshakePassRequested {
		// v5 password
		if b2[0] == 0x01 && b2[1] == 0x00 {
			// pasword ok
			newstate = handshakeAuthenticated
		}
	} else if c.state == handshakeAuthenticated {
		// v5 command response
		if b2[0] == 5 && b2[1] == 0 {
			// granted, will flush later
			c.state = handshakeGranted
			return n, err
		}
	} else if c.state == handshakeGranted {
		// accumulate the remainder of granted response
		return n, err
	}

	n2, err = c.flushHandshake(newstate)
	n = min(n, n2)
	return n, err
}

func (c *handshakeConn) flushHandshake(newstate int) (int, error) {
	c.state = newstate
	n64, err := c.headerBuf.WriteTo(c.TCPConn)
	return int(n64), err
}

// Object with Dispatch() method
type alpacaVDispatcher struct {
	handler       http.Handler
	handshakeConn *handshakeConn
}

func (d *alpacaVDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*v_transport.Link, error) {
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

	conn := newHTTPFilteringConn(reqPipeRd, resPipeWr)
	rw := &dummyResponseWriter{req: fakeReq, conn: conn}

	// Call Alpaca’s handler in background
	go d.handler.ServeHTTP(rw, fakeReq)
	statusOk, err := conn.waitReady(ctx)
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
	linkReader := &struct {
		io.ReadCloser
		buf.Reader
	}{ReadCloser: resPipeRd, Reader: buf.NewReader(resPipeRd)}

	linkWriter := &struct {
		io.WriteCloser
		buf.Writer
	}{WriteCloser: reqPipeWr, Writer: buf.NewWriter(reqPipeWr)}

	link := &v_transport.Link{
		Reader: linkReader, // response
		Writer: linkWriter, // request
	}

	_, err = d.handshakeConn.flushHandshake(handshakeEnded)
	if err != nil {
		return nil, err
	}
	return link, nil
}

func (d *alpacaVDispatcher) Close() error {
	// no-op and it's not called anyway
	return nil
}

func (d *alpacaVDispatcher) Start() error {
	panic("unimplemented")
}

func (d *alpacaVDispatcher) Type() interface{} {
	return alpacaVDispatcherType()
}

func alpacaVDispatcherType() interface{} {
	return (*alpacaVDispatcher)(nil)
}

// Wrapper that discards CONNECT response headers written to it and handles the
// payload normally. Created with the constructor function because of the chan
// field.
type httpDiscardingConn struct {
	reqPipeRd io.ReadCloser
	resPipeWr io.WriteCloser

	headerBuf  bytes.Buffer
	headerDone bool
	statusOK   bool
	headerErr  error

	readyCh chan struct{} // closed when headerDone is set
}

// Creates the object
func newHTTPFilteringConn(reqPipeRd io.ReadCloser, resPipeWr io.WriteCloser) *httpDiscardingConn {
	return &httpDiscardingConn{
		reqPipeRd: reqPipeRd,
		resPipeWr: resPipeWr,
		readyCh:   make(chan struct{}),
	}
}

// Waits until CONNECT response headers are discarded and the outcome is known
func (c *httpDiscardingConn) waitReady(ctx context.Context) (bool, error) {
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-c.readyCh:
		return c.statusOK, c.headerErr
	}
}

// Discards the CONNECT response headers and discards the error response body.
// Sets the status field and unblocks the waiters.
// It handles the success response body normally.
func (c *httpDiscardingConn) Write(b []byte) (int, error) {
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

// Unblocks the waiters
func (c *httpDiscardingConn) markReady(ok bool, err error) {
	if !c.headerDone {
		c.headerDone = true
		c.statusOK = ok
		c.headerErr = err
		close(c.readyCh)
	}
}

// Close implements net.Conn.
func (c *httpDiscardingConn) Close() error {
	c.reqPipeRd.Close()
	c.resPipeWr.Close()
	return nil
}

// Send EOF without closing the entire Link
// Note that V2Ray 4.19.1 only does graceful shutdown for uploads by closing
// Link.Writer but it doesn't call net.Conn.CloseWrite() for downloads and just
// keeps them open until the UplinkOnly timeout
func (c *httpDiscardingConn) CloseWrite() error {
	return c.resPipeWr.Close()
}

// Read implements net.Conn.
func (c *httpDiscardingConn) Read(b []byte) (n int, err error) {
	return c.reqPipeRd.Read(b)
}

// LocalAddr implements net.Conn.
func (c *httpDiscardingConn) LocalAddr() go_net.Addr {
	panic("unimplemented")
}

// RemoteAddr implements net.Conn.
func (c *httpDiscardingConn) RemoteAddr() go_net.Addr {
	panic("unimplemented")
}

// SetDeadline implements net.Conn.
func (c *httpDiscardingConn) SetDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetReadDeadline implements net.Conn.
func (c *httpDiscardingConn) SetReadDeadline(t time.Time) error {
	panic("unimplemented")
}

// SetWriteDeadline implements net.Conn.
func (c *httpDiscardingConn) SetWriteDeadline(t time.Time) error {
	panic("unimplemented")
}

// Object to pass to http.Handler.ServeHTTP()
type dummyResponseWriter struct {
	req  *http.Request
	conn net.Conn
}

// Called by Alpaca
func (w *dummyResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, nil, nil
}

func (w *dummyResponseWriter) Header() http.Header {
	return http.Header{}
}

func (w *dummyResponseWriter) Write(p []byte) (int, error) {
	return w.conn.Write(p)
}

// Called by Alpaca
func (w *dummyResponseWriter) WriteHeader(statusCode int) {
	var pref string
	if w.req.ProtoAtLeast(1, 1) {
		pref = "HTTP/1.1 "
	} else {
		pref = "HTTP/1.0 "
	}

	w.conn.Write([]byte(pref + strconv.Itoa(statusCode) + " Dummy Phrase\r\n\r\n"))
}
