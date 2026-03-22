/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package websocket

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	gorillaWs "github.com/gorilla/websocket"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
)

const (
	// incomingChanSize is the capacity of the buffered channel for received packets.
	incomingChanSize = 10_000

	// maxPacketSize is the maximum size of a single WireGuard packet (64 KiB).
	maxPacketSize = 65_536

	// wsBatchSize is the number of packets to process per batch read/write.
	wsBatchSize = 32

	// defaultConnectTimeout is the WebSocket handshake timeout for outgoing connections.
	defaultConnectTimeout = 5 * time.Second
)

// Bind implements conn.Bind for WebSocket tunnels
type Bind struct {
	mu            sync.RWMutex
	port          uint16
	incomingChan  chan *IncomingPacket
	connections   map[string]*Conn // key - endpoint string (host:port)
	server        *Server
	client        *Client
	slicePool     sync.Pool
	logger        *device.Logger
	serverStarted bool
	actualPort    uint16
	closed        bool
	done          chan struct{}
}

type IncomingPacket struct {
	Data     []byte
	Endpoint conn.Endpoint
}

func NewBind(logger *device.Logger, certFile, keyFile string, insecureSkipVerify bool, caFile, path string) (*Bind, error) {
	if logger == nil {
		logger = device.NewLogger(device.LogLevelError, "wireguard-ws ")
	}

	// Build client TLS config
	clientTLSConfig := &tls.Config{
		InsecureSkipVerify: insecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}
	if caFile != "" {
		caCert, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA certificate from %s", caFile)
		}
		clientTLSConfig.RootCAs = caCertPool
	}

	bind := &Bind{
		incomingChan: make(chan *IncomingPacket, incomingChanSize),
		connections:  make(map[string]*Conn),
		slicePool: sync.Pool{
			New: func() any { buf := make([]byte, maxPacketSize); return &buf },
		},
		logger: logger,
		done:   make(chan struct{}),
	}

	// Server is only created when TLS certificate is provided
	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}
		bind.server = NewServer(cert, path, func(conn *Conn) {
			bind.handleConnection(conn)
		})
		logger.Verbosef("websocket server configured with cert: %s", certFile)
	} else {
		logger.Verbosef("websocket client-only mode (no server certificate)")
	}

	bind.client = NewClient(clientTLSConfig, path, defaultConnectTimeout)

	return bind, nil
}

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	if b.closed {
		b.incomingChan = make(chan *IncomingPacket, incomingChanSize)
		b.done = make(chan struct{})
		b.closed = false
	}
	b.port = port
	b.actualPort = port
	b.mu.Unlock()

	// Start server immediately if port is non-zero (real listen-port from UAPI)
	// Don't start when port=0 as no one can connect to port 0
	if port != 0 {
		if err := b.ensureServerStarted(); err != nil {
			return nil, 0, fmt.Errorf("failed to start websocket server on port %d: %w", port, err)
		}
	}

	receiveFunc := func(data [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		packet, ok := <-b.incomingChan
		if !ok {
			return 0, net.ErrClosed
		}
		if len(packet.Data) > len(data[0]) {
			return 0, fmt.Errorf("buffer too small")
		}
		copy(data[0], packet.Data)
		sizes[0] = len(packet.Data)
		eps[0] = packet.Endpoint

		processed := 1
		for i := processed; i < len(data); i++ {
			select {
			case packet := <-b.incomingChan:
				if len(packet.Data) > len(data[i]) {
					return processed, nil
				}
				copy(data[i], packet.Data)
				sizes[i] = len(packet.Data)
				eps[i] = packet.Endpoint
				processed++
			default:
				return processed, nil
			}
		}
		return processed, nil
	}

	return []conn.ReceiveFunc{receiveFunc}, b.actualPort, nil
}

// ensureServerStarted starts the server if it hasn't been started yet
func (b *Bind) ensureServerStarted() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.serverStarted || b.server == nil {
		return nil
	}

	// Get actual port and server start function
	actualPort, startServer, err := b.server.ListenAndServeWithActualPort(fmt.Sprintf(":%d", b.port))
	if err != nil {
		b.logger.Errorf("failed to prepare WebSocket server on port %d: %v", b.port, err)
		return fmt.Errorf("failed to prepare websocket server: %w", err)
	}

	// Update actual port first
	b.actualPort = actualPort
	b.serverStarted = true
	b.logger.Verbosef("websocket server started on port %d", actualPort)

	// Now start the server in background
	go func() {
		if err := startServer(); err != nil && err != http.ErrServerClosed {
			b.logger.Errorf("websocket server failed on port %d: %v", actualPort, err)
		}
	}()

	return nil
}

func (b *Bind) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Close all connections
	for key, conn := range b.connections {
		conn.Close()
		delete(b.connections, key)
	}

	// Close server
	if b.server != nil && b.serverStarted {
		b.server.Close()
		b.serverStarted = false
	}

	// Signal shutdown and close the incoming channel
	if !b.closed {
		close(b.done)
		close(b.incomingChan)
		b.closed = true
	}

	return nil
}

func (b *Bind) BatchSize() int {
	return wsBatchSize
}

func (b *Bind) Send(data [][]byte, endpoint conn.Endpoint) error {
	if len(data) == 0 {
		return nil
	}
	customEP, ok := endpoint.(*Endpoint)
	if !ok {
		b.logger.Errorf("websocket send: invalid endpoint type: %T", endpoint)
		return fmt.Errorf("invalid endpoint type")
	}
	if !customEP.AddrPort.IsValid() {
		return fmt.Errorf("invalid endpoint address: %s", customEP.AddrPort.String())
	}

	// Ensure server is started when we actually need to send data
	if err := b.ensureServerStarted(); err != nil {
		return err
	}

	// Use endpoint string as connection key
	endpointKey := customEP.DstToString()

	// fast-path: connection already exists?
	b.mu.RLock()
	conn, exists := b.connections[endpointKey]
	b.mu.RUnlock()
	if !exists {
		// Double-checked locking to prevent duplicate connections
		b.mu.Lock()
		conn, exists = b.connections[endpointKey]
		if !exists {
			var err error
			conn, err = b.establishConnection(customEP)
			if err != nil {
				b.mu.Unlock()
				return fmt.Errorf("failed to establish connection: %w", err)
			}
			b.connections[endpointKey] = conn
		}
		b.mu.Unlock()
	}

	total := 0
	for _, p := range data {
		if len(p) == 0 {
			continue
		}
		total += 4 + len(p)
	}
	buf := *b.slicePool.Get().(*[]byte)
	if cap(buf) < total {
		buf = make([]byte, total)
	}
	buf = buf[:total]

	off := 0
	for _, p := range data {
		if len(p) == 0 {
			continue
		}
		binary.BigEndian.PutUint32(buf[off:], uint32(len(p)))
		off += 4
		copy(buf[off:], p)
		off += len(p)
	}

	if _, err := conn.Write(buf); err != nil {
		b.mu.Lock()
		if b.connections[endpointKey] == conn {
			delete(b.connections, endpointKey)
		}
		b.mu.Unlock()
		b.slicePool.Put(&buf)
		return err
	}
	b.slicePool.Put(&buf)
	return nil
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	// Fast path: already an IP:port
	if addrPort, err := netip.ParseAddrPort(s); err == nil {
		return &Endpoint{AddrPort: addrPort}, nil
	}

	// Slow path: hostname:port — resolve DNS
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse endpoint %q: %w", s, err)
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("invalid port in endpoint %q: %w", s, err)
	}
	ips, err := net.DefaultResolver.LookupHost(context.Background(), host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve endpoint %q: %w", s, err)
	}
	addr, err := netip.ParseAddr(ips[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse resolved address %q: %w", ips[0], err)
	}
	return &Endpoint{
		AddrPort: netip.AddrPortFrom(addr, uint16(port)),
		Hostname: host,
	}, nil
}

func (b *Bind) SetMark(mark uint32) error {
	// For WebSocket transport, socket marking is not applicable
	// Return nil to indicate success (no-op)
	return nil
}

func (b *Bind) handleConnection(conn *Conn) {
	b.logger.Verbosef("incoming websocket connection from %s", conn.RemoteAddr())

	connKey := conn.RemoteAddr().String()

	b.mu.Lock()
	b.connections[connKey] = conn
	b.mu.Unlock()

	defer func() {
		conn.Close()
		b.logger.Verbosef("closed incoming connection from %s", conn.RemoteAddr())
	}()

	// readFromConnection handles cleanup of b.connections
	b.readFromConnection(conn, connKey, false)
}

func (b *Bind) establishConnection(endpoint *Endpoint) (*Conn, error) {
	if !endpoint.AddrPort.IsValid() {
		return nil, fmt.Errorf("invalid endpoint: %s", endpoint.AddrPort.String())
	}

	// Use hostname for URL if available (enables correct TLS SNI),
	// otherwise fall back to IP:port
	var connectAddr string
	if endpoint.Hostname != "" {
		connectAddr = fmt.Sprintf("%s:%d", endpoint.Hostname, endpoint.AddrPort.Port())
	} else {
		connectAddr = endpoint.AddrPort.String()
	}

	b.logger.Verbosef("establishing websocket connection to: %s", connectAddr)

	conn, err := b.client.Connect(connectAddr)
	if err != nil {
		b.logger.Errorf("websocket connection failed to %s: %v", connectAddr, err)
		return nil, fmt.Errorf("websocket connection failed to %s: %w", connectAddr, err)
	}

	b.logger.Verbosef("websocket connection established to: %s", connectAddr)

	go b.readFromConnection(conn, endpoint.DstToString(), true)

	return conn, nil
}

// enqueuePacket safely sends a packet to the incoming channel.
// Returns false if the bind is shutting down or the packet was dropped.
func (b *Bind) enqueuePacket(pkt *IncomingPacket) bool {
	select {
	case <-b.done:
		return false
	default:
	}

	select {
	case b.incomingChan <- pkt:
		return true
	case <-b.done:
		return false
	default:
		// Overflow: drop oldest packet to make room
		select {
		case <-b.incomingChan:
			b.logger.Verbosef("incoming packet queue full, dropped oldest packet")
		default:
		}
		select {
		case b.incomingChan <- pkt:
			return true
		case <-b.done:
			return false
		default:
			b.logger.Verbosef("incoming packet dropped: queue still full")
			return false
		}
	}
}

// isNormalClose returns true for errors that indicate a normal connection close
// (client disconnect, graceful shutdown) rather than an unexpected failure.
func isNormalClose(err error) bool {
	if err == nil {
		return false
	}
	if gorillaWs.IsCloseError(err, gorillaWs.CloseNormalClosure, gorillaWs.CloseGoingAway, gorillaWs.CloseAbnormalClosure) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "closed") || strings.Contains(s, "unexpected EOF") || strings.Contains(s, "use of closed")
}

func (b *Bind) readFromConnection(conn *Conn, endpointKey string, ownsConn bool) {
	if ownsConn {
		defer conn.Close()
	}
	defer func() {
		b.mu.Lock()
		delete(b.connections, endpointKey)
		b.mu.Unlock()
		b.logger.Verbosef("connection %s closed", endpointKey)
	}()

	var hdr [4]byte

	for {
		if _, err := io.ReadFull(conn, hdr[:]); err != nil {
			if err != io.EOF && !isNormalClose(err) {
				b.logger.Errorf("size read err from %s: %v", endpointKey, err)
			}
			break
		}
		sz := binary.BigEndian.Uint32(hdr[:])
		if sz == 0 || sz > maxPacketSize {
			b.logger.Errorf("bad pkt %d from %s", sz, endpointKey)
			continue
		}

		// Read into pooled buffer, then copy out immediately
		bufPtr := b.slicePool.Get().(*[]byte)
		buf := *bufPtr
		if cap(buf) < int(sz) {
			buf = make([]byte, sz)
		}
		pkt := buf[:sz]

		if _, err := io.ReadFull(conn, pkt); err != nil {
			b.logger.Errorf("pkt read err from %s: %v", endpointKey, err)
			b.slicePool.Put(bufPtr)
			break
		}

		// Copy packet data so pool buffer can be returned immediately
		packetData := make([]byte, sz)
		copy(packetData, pkt)
		b.slicePool.Put(bufPtr)

		remoteAddr := conn.RemoteAddr().String()
		addrPort, err := netip.ParseAddrPort(remoteAddr)
		if err != nil {
			b.logger.Errorf("failed to parse remote address %s: %v", remoteAddr, err)
			continue
		}

		ep := &Endpoint{AddrPort: addrPort}
		b.enqueuePacket(&IncomingPacket{Data: packetData, Endpoint: ep})
	}
}
