/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package websocket

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
)

// ConnectionHandler handles new tunnel connections
type ConnectionHandler func(conn *Conn)

// TunnelAddr implements net.Addr for tunnel connections
type TunnelAddr struct {
	network string
	address string
}

func (a *TunnelAddr) Network() string { return a.network }
func (a *TunnelAddr) String() string  { return a.address }

// Server handles incoming tunnel connections
type Server struct {
	server     *http.Server
	handler    ConnectionHandler
	tlsConfig  *tls.Config
	wsUpgrader websocket.Upgrader
	path       string
}

// NewServer creates a new tunnel server with TLS certificate, path and connection handler
func NewServer(cert tls.Certificate, path string, handler ConnectionHandler) *Server {
	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates:           []tls.Certificate{cert},
		NextProtos:             []string{"http/1.1"},
		SessionTicketsDisabled: false,
		ClientSessionCache:     tls.NewLRUClientSessionCache(100),
		CipherSuites: []uint16{
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, // Required for HTTP/2
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		},
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS13,
	}

	return &Server{
		handler:   handler,
		tlsConfig: tlsConfig,
		path:      path,
		wsUpgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins
			},
			Subprotocols:    []string{"tunnel"},
			ReadBufferSize:  32 << 10, // 32KB
			WriteBufferSize: 32 << 10, // 32KB
		},
	}
}

// ListenAndServeWithActualPort binds a TCP listener to discover the actual port,
// wraps it with TLS, and returns a start function. The listener is never released
// between discovery and serving, avoiding TOCTOU port races.
func (s *Server) ListenAndServeWithActualPort(addr string) (uint16, func() error, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return 0, nil, err
	}

	actualPort := uint16(listener.Addr().(*net.TCPAddr).Port)

	// Wrap the existing listener with TLS — no close/reopen needed
	tlsListener := tls.NewListener(listener, s.tlsConfig)

	mux := http.NewServeMux()
	mux.HandleFunc(s.path, s.handleWebSocket)

	s.server = &http.Server{
		Handler:           mux,
		TLSConfig:         s.tlsConfig,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       90 * time.Second,
		MaxHeaderBytes:    1 << 20, // 1MB
	}

	startServer := func() error {
		return s.server.Serve(tlsListener)
	}

	return actualPort, startServer, nil
}

// Close shuts down the server
func (s *Server) Close() error {
	if s.server != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return s.server.Shutdown(ctx)
	}
	return nil
}

// handleWebSocket handles WebSocket upgrade and creates tunnel connections
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	wsConn, err := s.wsUpgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	conn := &Conn{
		wsConn:     wsConn,
		localAddr:  &TunnelAddr{network: "tcp", address: r.Host},
		remoteAddr: &TunnelAddr{network: "tcp", address: r.RemoteAddr},
	}

	if s.handler != nil {
		go s.handler(conn)
	}
}

// Client creates outgoing tunnel connections
type Client struct {
	wsDialer *websocket.Dialer
	path     string
}

// NewClient creates a new tunnel client with the given TLS config, path and handshake timeout
func NewClient(tlsConfig *tls.Config, path string, timeout time.Duration) *Client {
	wsDialer := &websocket.Dialer{
		HandshakeTimeout: timeout,
		TLSClientConfig:  tlsConfig,
		Subprotocols:     []string{"tunnel"},
		ReadBufferSize:   32 << 10, // 32KB
		WriteBufferSize:  32 << 10, // 32KB
	}

	return &Client{
		wsDialer: wsDialer,
		path:     path,
	}
}

// Connect establishes a connection to the tunnel server
func (c *Client) Connect(addr string) (*Conn, error) {
	if !strings.HasPrefix(addr, "wss://") && !strings.HasPrefix(addr, "ws://") {
		addr = "wss://" + addr
	}
	if !strings.HasSuffix(addr, c.path) {
		addr += c.path
	}

	wsConn, _, err := c.wsDialer.Dial(addr, nil)
	if err != nil {
		return nil, fmt.Errorf("websocket connection failed: %w", err)
	}

	return &Conn{
		wsConn:     wsConn,
		localAddr:  &TunnelAddr{network: "tcp", address: wsConn.LocalAddr().String()},
		remoteAddr: &TunnelAddr{network: "tcp", address: wsConn.RemoteAddr().String()},
	}, nil
}

// Conn implements net.Conn over WebSocket tunnel
type Conn struct {
	wsConn        *websocket.Conn
	reader        io.Reader
	localAddr     net.Addr
	remoteAddr    net.Addr
	closed        atomic.Bool
	readMu        sync.Mutex
	writeMu       sync.Mutex
	readDeadline  atomic.Int64 // Unix nano time
	writeDeadline atomic.Int64 // Unix nano time
}

// Implementation of net.Conn interface

func (c *Conn) Read(b []byte) (n int, err error) {
	if c.closed.Load() {
		return 0, io.EOF
	}

	c.readMu.Lock()
	defer c.readMu.Unlock()

	// Apply deadline to underlying WebSocket connection
	if deadline := c.readDeadline.Load(); deadline != 0 {
		t := time.Unix(0, deadline)
		if time.Now().After(t) {
			return 0, fmt.Errorf("read deadline exceeded")
		}
		c.wsConn.SetReadDeadline(t)
	} else {
		c.wsConn.SetReadDeadline(time.Time{})
	}

	if c.reader == nil {
		messageType, reader, err := c.wsConn.NextReader()
		if err != nil {
			return 0, err
		}
		if messageType != websocket.BinaryMessage {
			return 0, fmt.Errorf("expected binary message, got %d", messageType)
		}
		c.reader = reader
	}

	n, err = c.reader.Read(b)
	if err == io.EOF {
		c.reader = nil
		err = nil
	}
	return n, err
}

func (c *Conn) Write(b []byte) (n int, err error) {
	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.closed.Load() {
		return 0, io.ErrClosedPipe
	}

	// Apply deadline to underlying WebSocket connection
	if deadline := c.writeDeadline.Load(); deadline != 0 {
		t := time.Unix(0, deadline)
		if time.Now().After(t) {
			return 0, fmt.Errorf("write deadline exceeded")
		}
		c.wsConn.SetWriteDeadline(t)
	} else {
		c.wsConn.SetWriteDeadline(time.Time{})
	}

	writer, err := c.wsConn.NextWriter(websocket.BinaryMessage)
	if err != nil {
		return 0, err
	}

	n, err = writer.Write(b)
	if closeErr := writer.Close(); closeErr != nil && err == nil {
		err = closeErr
	}
	return n, err
}

func (c *Conn) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		return c.wsConn.Close()
	}
	return nil
}

func (c *Conn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	var deadline int64
	if !t.IsZero() {
		deadline = t.UnixNano()
	}
	c.readDeadline.Store(deadline)
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	var deadline int64
	if !t.IsZero() {
		deadline = t.UnixNano()
	}
	c.writeDeadline.Store(deadline)
	return nil
}
