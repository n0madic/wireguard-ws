/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package websocket

import (
	"net/netip"
	"testing"

	"golang.zx2c4.com/wireguard/device"
)

func TestBind_ParseEndpoint(t *testing.T) {
	logger := device.NewLogger(device.LogLevelError, "test")
	bind := &Bind{logger: logger}

	tests := []struct {
		name         string
		input        string
		wantErr      bool
		want         string
		wantHostname string
	}{
		{
			name:    "valid IPv4",
			input:   "192.168.1.1:51820",
			wantErr: false,
			want:    "192.168.1.1:51820",
		},
		{
			name:    "valid IPv6",
			input:   "[2001:db8::1]:8080",
			wantErr: false,
			want:    "[2001:db8::1]:8080",
		},
		{
			name:    "valid IPv6 localhost",
			input:   "[::1]:443",
			wantErr: false,
			want:    "[::1]:443",
		},
		{
			name:         "hostname localhost",
			input:        "localhost:8080",
			wantErr:      false,
			wantHostname: "localhost",
		},
		{
			name:    "invalid format",
			input:   "invalid",
			wantErr: true,
		},
		{
			name:    "missing port",
			input:   "192.168.1.1",
			wantErr: true,
		},
		{
			name:    "IPv6 without brackets",
			input:   "2001:db8::1:8080",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ep, err := bind.ParseEndpoint(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseEndpoint(%s) expected error", tt.input)
				}
				return
			}
			if err != nil {
				t.Errorf("ParseEndpoint(%s) error = %v", tt.input, err)
				return
			}

			wsEp, ok := ep.(*Endpoint)
			if !ok {
				t.Errorf("ParseEndpoint(%s) returned wrong type", tt.input)
				return
			}

			if tt.want != "" {
				if got := wsEp.DstToString(); got != tt.want {
					t.Errorf("ParseEndpoint(%s).DstToString() = %v, want %v", tt.input, got, tt.want)
				}
			}

			if tt.wantHostname != "" {
				if wsEp.Hostname != tt.wantHostname {
					t.Errorf("ParseEndpoint(%s).Hostname = %v, want %v", tt.input, wsEp.Hostname, tt.wantHostname)
				}
			}

			// IP endpoints should have empty hostname
			if tt.wantHostname == "" && wsEp.Hostname != "" {
				t.Errorf("ParseEndpoint(%s).Hostname = %v, want empty", tt.input, wsEp.Hostname)
			}
		})
	}
}

func TestIncomingPacket(t *testing.T) {
	addrPort := netip.MustParseAddrPort("192.168.1.1:51820")
	ep := &Endpoint{AddrPort: addrPort}
	data := []byte("test packet")

	packet := &IncomingPacket{
		Data:     data,
		Endpoint: ep,
	}

	if string(packet.Data) != "test packet" {
		t.Errorf("Data = %s, want 'test packet'", string(packet.Data))
	}

	if packet.Endpoint.DstToString() != "192.168.1.1:51820" {
		t.Errorf("Endpoint = %s, want '192.168.1.1:51820'", packet.Endpoint.DstToString())
	}
}
