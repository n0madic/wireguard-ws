/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package websocket

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

func TestConn_RemoteAddr(t *testing.T) {
	// Create a mock websocket connection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade error: %v", err)
			return
		}
		defer ws.Close()

		conn := &Conn{
			wsConn:     ws,
			remoteAddr: &TunnelAddr{network: "tcp", address: r.RemoteAddr},
		}
		addr := conn.RemoteAddr()
		if addr == nil {
			t.Error("RemoteAddr() returned nil")
		}
	}))
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"

	// Connect to the test server
	ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}
	defer ws.Close()

	// Wait a bit for the server handler to run
	time.Sleep(100 * time.Millisecond)
}

func TestConn_ReadWrite(t *testing.T) {
	// Create a pair of connected websocket connections
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade error: %v", err)
			return
		}
		defer ws.Close()

		// Echo back what we receive
		for {
			messageType, data, err := ws.ReadMessage()
			if err != nil {
				break
			}
			if err := ws.WriteMessage(messageType, data); err != nil {
				break
			}
		}
	}))
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"

	// Connect to the test server
	ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}
	defer ws.Close()

	conn := &Conn{wsConn: ws}

	// Test Write
	testData := []byte("hello world")
	n, err := conn.Write(testData)
	if err != nil {
		t.Errorf("Write error: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Write returned %d, want %d", n, len(testData))
	}

	// Test Read
	buffer := make([]byte, 100)
	n, err = conn.Read(buffer)
	if err != nil {
		t.Errorf("Read error: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Read returned %d, want %d", n, len(testData))
	}
	if string(buffer[:n]) != string(testData) {
		t.Errorf("Read data = %s, want %s", string(buffer[:n]), string(testData))
	}
}

func TestConn_Close(t *testing.T) {
	// Create a mock websocket connection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade error: %v", err)
			return
		}
		defer ws.Close()

		// Keep connection alive
		ws.ReadMessage()
	}))
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"

	// Connect to the test server
	ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}

	conn := &Conn{wsConn: ws}

	// Test Close
	err = conn.Close()
	if err != nil {
		t.Errorf("Close error: %v", err)
	}

	// Subsequent operations should fail
	_, err = conn.Write([]byte("test"))
	if err == nil {
		t.Error("Write after Close should fail")
	}
}

func TestServer_ServeHTTP_NonWebSocket(t *testing.T) {
	cert := tls.Certificate{}
	handler := func(conn *Conn) {}
	server := NewServer(cert, "/ws", handler)

	// Create a request recorder
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "/", nil)

	// This should fail because it's not a WebSocket upgrade request
	server.handleWebSocket(recorder, request)

	if recorder.Code == http.StatusSwitchingProtocols {
		t.Error("Expected non-WebSocket request to fail")
	}
}

func TestConn_ReadWriteDeadlines(t *testing.T) {
	// Create a pair of connected websocket connections
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upgrader := websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool { return true },
		}
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			t.Errorf("Upgrade error: %v", err)
			return
		}
		defer ws.Close()

		// Don't read anything to test deadline
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	// Convert HTTP URL to WebSocket URL
	u, _ := url.Parse(server.URL)
	u.Scheme = "ws"

	// Connect to the test server
	ws, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		t.Fatalf("Dial error: %v", err)
	}
	defer ws.Close()

	conn := &Conn{wsConn: ws}

	// Test SetReadDeadline
	deadline := time.Now().Add(100 * time.Millisecond)
	err = conn.SetReadDeadline(deadline)
	if err != nil {
		t.Errorf("SetReadDeadline error: %v", err)
	}

	// Test SetWriteDeadline
	err = conn.SetWriteDeadline(deadline)
	if err != nil {
		t.Errorf("SetWriteDeadline error: %v", err)
	}

	// Test SetDeadline
	err = conn.SetDeadline(deadline)
	if err != nil {
		t.Errorf("SetDeadline error: %v", err)
	}
}
