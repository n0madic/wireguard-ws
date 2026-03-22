/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

package main

import (
	"os"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/websocket"
)

const (
	ENV_WG_WS           = "WG_WS"
	ENV_WG_WS_CERT_FILE = "WG_WS_CERT_FILE"
	ENV_WG_WS_KEY_FILE  = "WG_WS_KEY_FILE"
	ENV_WG_WS_INSECURE  = "WG_WS_INSECURE"
	ENV_WG_WS_CA_FILE   = "WG_WS_CA_FILE"
	ENV_WG_WS_PATH      = "WG_WS_PATH"
)

// createBind returns a WebSocket bind if WG_WS=1 or cert/key files are set,
// otherwise returns the standard UDP bind.
func createBind(logger *device.Logger) conn.Bind {
	wsCertFile := os.Getenv(ENV_WG_WS_CERT_FILE)
	wsKeyFile := os.Getenv(ENV_WG_WS_KEY_FILE)
	wsEnabled := os.Getenv(ENV_WG_WS) == "1" || (wsCertFile != "" && wsKeyFile != "")
	if wsEnabled {
		wsInsecure := os.Getenv(ENV_WG_WS_INSECURE) == "1"
		wsCAFile := os.Getenv(ENV_WG_WS_CA_FILE)
		wsPath := os.Getenv(ENV_WG_WS_PATH)
		if wsPath == "" {
			wsPath = "/ws"
		} else if wsPath[0] != '/' {
			wsPath = "/" + wsPath
		}
		logger.Verbosef("WebSocket transport enabled (path: %s)", wsPath)
		bind, err := websocket.NewBind(logger, wsCertFile, wsKeyFile, wsInsecure, wsCAFile, wsPath)
		if err != nil {
			logger.Errorf("Failed to create WebSocket bind: %v", err)
			os.Exit(1)
		}
		return bind
	}
	logger.Verbosef("Using standard UDP transport")
	return conn.NewDefaultBind()
}
