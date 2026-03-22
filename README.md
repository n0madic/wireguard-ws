# WireGuard-WS: WebSocket Transport for [WireGuard](https://www.wireguard.com/)

This is a fork of [wireguard-go](https://git.zx2c4.com/wireguard-go/) with added WebSocket transport support. It allows WireGuard to tunnel through environments where UDP is blocked — corporate networks, restrictive firewalls, or HTTP proxies. Fully compatible with standard `wg` and `wg-quick` tools.

## Usage

Most Linux kernel WireGuard users are used to adding an interface with `ip link add wg0 type wireguard`. With wireguard-ws, instead simply run:

```
$ wireguard-ws wg0
```

This will create an interface and fork into the background. To remove the interface, use the usual `ip link del wg0`, or if your system does not support removing interfaces directly, you may instead remove the control socket via `rm -f /var/run/wireguard/wg0.sock`, which will result in wireguard-ws shutting down.

To run wireguard-ws without forking to the background, pass `-f` or `--foreground`:

```
$ wireguard-ws -f wg0
```

When an interface is running, you may use [`wg(8)`](https://git.zx2c4.com/wireguard-tools/about/src/man/wg.8) to configure it, as well as the usual `ip(8)` and `ifconfig(8)` commands.

To run with more logging you may set the environment variable `LOG_LEVEL=debug`.

## WebSocket Transport

WireGuard-Go supports WebSocket as an alternative transport to UDP. This is useful in environments where UDP traffic is blocked or filtered, such as corporate networks or when tunneling through HTTP proxies.

### WebSocket Usage

Enable WebSocket mode with `WG_WS=1`. Server nodes additionally need TLS certificates:

```bash
# Server (accepts incoming WebSocket connections)
$ WG_WS=1 WG_WS_CERT_FILE=server.pem WG_WS_KEY_FILE=server-key.pem wireguard-ws wg0

# Client (connects to WebSocket server, no certificate needed)
$ WG_WS=1 WG_WS_INSECURE=1 wireguard-ws wg0
```

Generate self-signed certificates for testing:

```bash
$ openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server.pem -days 365 -nodes -subj "/CN=your-domain.com"
```

### WebSocket Configuration

Configure peers to use WebSocket endpoints in the standard format `host:port`:

```bash
$ wg set wg0 peer PEER_PUBLIC_KEY endpoint example.com:8443 allowed-ips 10.0.0.2/32
```

The WebSocket server will listen on the same port specified via `wg set wg0 listen-port PORT` or default to a random port. Clients connect to `wss://host:port/ws`.

### WebSocket Features

- **TLS 1.2+ encryption** with modern cipher suites
- **Transparent reconnection** via WireGuard's built-in retransmission
- **Full compatibility** with standard WireGuard tools (`wg`, `wg-quick`)
- **Seamless fallback** - uses UDP transport when WebSocket certificates are not provided
- **Performance optimized** with connection pooling and batch packet processing

## Platforms

### Linux

This will run on Linux; however you should instead use the kernel module, which is faster and better integrated into the OS. See the [installation page](https://www.wireguard.com/install/) for instructions.

### macOS

This runs on macOS using the utun driver. It does not yet support sticky sockets, and won't support fwmarks because of Darwin limitations. Since the utun driver cannot have arbitrary interface names, you must either use `utun[0-9]+` for an explicit interface name or `utun` to have the kernel select one for you. If you choose `utun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

### Windows

This runs on Windows, but you should instead use it from the more [fully featured Windows app](https://git.zx2c4.com/wireguard-windows/about/), which uses this as a module.

### FreeBSD

This will run on FreeBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_USER_COOKIE`.

### OpenBSD

This will run on OpenBSD. It does not yet support sticky sockets. Fwmark is mapped to `SO_RTABLE`. Since the tun driver cannot have arbitrary interface names, you must either use `tun[0-9]+` for an explicit interface name or `tun` to have the program select one for you. If you choose `tun` as the interface name, and the environment variable `WG_TUN_NAME_FILE` is defined, then the actual name of the interface chosen by the kernel is written to the file specified by that variable.

## Building

This requires an installation of the latest version of [Go](https://go.dev/).

```
$ git clone https://github.com/n0madic/wireguard-ws
$ cd wireguard-ws
$ make
```

## Environment Variables

### Standard Variables
- `LOG_LEVEL`: Set logging level (`debug`, `verbose`, `error`, `silent`)
- `WG_TUN_FD`: Use existing TUN file descriptor
- `WG_UAPI_FD`: Use existing UAPI file descriptor
- `WG_PROCESS_FOREGROUND`: Force foreground mode
- `WG_TUN_NAME_FILE`: Write actual interface name to file

### WebSocket Variables
- `WG_WS`: Set to `1` to enable WebSocket transport mode
- `WG_WS_CERT_FILE`: Path to TLS certificate file for server (optional, enables incoming connections)
- `WG_WS_KEY_FILE`: Path to TLS private key file (required if cert file is set)
- `WG_WS_INSECURE`: Set to `1` to skip TLS certificate verification for outgoing connections (default: verify)
- `WG_WS_CA_FILE`: Path to custom CA certificate file for verifying peer certificates
- `WG_WS_PATH`: WebSocket endpoint path (default: `/ws`)

Setting `WG_WS_CERT_FILE` and `WG_WS_KEY_FILE` without `WG_WS=1` also enables WebSocket mode.

## License

    Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.

    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is furnished to do
    so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
