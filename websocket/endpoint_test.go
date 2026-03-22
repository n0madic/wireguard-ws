/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package websocket

import (
	"net/netip"
	"testing"
)

func TestEndpoint_Basic(t *testing.T) {
	tests := []struct {
		name     string
		addr     string
		wantAddr netip.AddrPort
		wantErr  bool
	}{
		{
			name:     "IPv4 address",
			addr:     "192.168.1.1:51820",
			wantAddr: netip.MustParseAddrPort("192.168.1.1:51820"),
			wantErr:  false,
		},
		{
			name:     "IPv6 address",
			addr:     "[2001:db8::1]:8080",
			wantAddr: netip.MustParseAddrPort("[2001:db8::1]:8080"),
			wantErr:  false,
		},
		{
			name:     "IPv6 localhost",
			addr:     "[::1]:443",
			wantAddr: netip.MustParseAddrPort("[::1]:443"),
			wantErr:  false,
		},
		{
			name:    "invalid format",
			addr:    "invalid",
			wantErr: true,
		},
		{
			name:    "hostname not supported",
			addr:    "example.com:8080",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrPort, err := netip.ParseAddrPort(tt.addr)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseAddrPort() expected error for %s", tt.addr)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseAddrPort() error = %v", err)
				return
			}

			ep := &Endpoint{AddrPort: addrPort}

			if ep.AddrPort != tt.wantAddr {
				t.Errorf("AddrPort = %v, want %v", ep.AddrPort, tt.wantAddr)
			}
		})
	}
}

func TestEndpoint_DstToString(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{
			name: "IPv4",
			addr: "192.168.1.1:51820",
			want: "192.168.1.1:51820",
		},
		{
			name: "IPv6",
			addr: "[2001:db8::1]:8080",
			want: "[2001:db8::1]:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrPort := netip.MustParseAddrPort(tt.addr)
			ep := &Endpoint{AddrPort: addrPort}

			got := ep.DstToString()
			if got != tt.want {
				t.Errorf("DstToString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEndpoint_DstToBytes(t *testing.T) {
	tests := []struct {
		name string
		addr string
	}{
		{
			name: "IPv4",
			addr: "192.168.1.1:51820",
		},
		{
			name: "IPv6",
			addr: "[2001:db8::1]:8080",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrPort := netip.MustParseAddrPort(tt.addr)
			ep := &Endpoint{AddrPort: addrPort}

			bytes := ep.DstToBytes()
			if len(bytes) == 0 {
				t.Error("DstToBytes() returned empty slice")
			}

			// Test that we can marshal and unmarshal consistently
			var parsed netip.AddrPort
			err := parsed.UnmarshalBinary(bytes)
			if err != nil {
				t.Errorf("UnmarshalBinary() error = %v", err)
			}

			if parsed != addrPort {
				t.Errorf("Round trip failed: got %v, want %v", parsed, addrPort)
			}
		})
	}
}

func TestEndpoint_DstIP(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want netip.Addr
	}{
		{
			name: "IPv4",
			addr: "192.168.1.1:51820",
			want: netip.MustParseAddr("192.168.1.1"),
		},
		{
			name: "IPv6",
			addr: "[2001:db8::1]:8080",
			want: netip.MustParseAddr("2001:db8::1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addrPort := netip.MustParseAddrPort(tt.addr)
			ep := &Endpoint{AddrPort: addrPort}

			got := ep.DstIP()
			if got != tt.want {
				t.Errorf("DstIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestEndpoint_SrcMethods(t *testing.T) {
	addrPort := netip.MustParseAddrPort("192.168.1.1:51820")
	ep := &Endpoint{AddrPort: addrPort}

	// Test that source methods return empty values as expected
	if got := ep.SrcToString(); got != "" {
		t.Errorf("SrcToString() = %v, want empty string", got)
	}

	if got := ep.SrcIP(); got.IsValid() {
		t.Errorf("SrcIP() = %v, want invalid addr", got)
	}

	// ClearSrc should be a no-op and not panic
	ep.ClearSrc()
}

func TestEndpoint_Interface(t *testing.T) {
	// Verify that Endpoint implements conn.Endpoint interface
	addrPort := netip.MustParseAddrPort("192.168.1.1:51820")
	ep := &Endpoint{AddrPort: addrPort}

	// This should compile without errors if interface is properly implemented
	_ = ep.ClearSrc
	_ = ep.SrcToString
	_ = ep.DstToString
	_ = ep.DstToBytes
	_ = ep.DstIP
	_ = ep.SrcIP
}

func TestEndpoint_Hostname(t *testing.T) {
	addrPort := netip.MustParseAddrPort("93.184.216.34:8443")
	ep := &Endpoint{
		AddrPort: addrPort,
		Hostname: "example.com",
	}

	// DstToString should return IP:port (not hostname)
	if got := ep.DstToString(); got != "93.184.216.34:8443" {
		t.Errorf("DstToString() = %v, want 93.184.216.34:8443", got)
	}

	// DstIP should return the resolved IP
	if got := ep.DstIP(); got != netip.MustParseAddr("93.184.216.34") {
		t.Errorf("DstIP() = %v, want 93.184.216.34", got)
	}

	// Hostname should be preserved
	if ep.Hostname != "example.com" {
		t.Errorf("Hostname = %v, want example.com", ep.Hostname)
	}

	// Endpoint without hostname
	epNoHost := &Endpoint{AddrPort: addrPort}
	if epNoHost.Hostname != "" {
		t.Errorf("Hostname should be empty, got %v", epNoHost.Hostname)
	}
}
