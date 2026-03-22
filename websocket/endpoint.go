/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package websocket

import (
	"net/netip"
)

// Endpoint implements conn.Endpoint for WebSocket connections
type Endpoint struct {
	AddrPort netip.AddrPort // Resolved IP address:port
	Hostname string         // Original hostname for TLS SNI (empty if endpoint was IP)
}

func (e *Endpoint) ClearSrc()           {}
func (e *Endpoint) SrcToString() string { return "" }
func (e *Endpoint) DstToString() string {
	return e.AddrPort.String()
}
func (e *Endpoint) DstToBytes() []byte {
	b, _ := e.AddrPort.MarshalBinary()
	return b
}
func (e *Endpoint) SrcIP() netip.Addr {
	// For outgoing traffic IP is not used, return empty address
	return netip.Addr{}
}
func (e *Endpoint) DstIP() netip.Addr {
	return e.AddrPort.Addr()
}
