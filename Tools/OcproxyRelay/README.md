# External OpenConnect SOCKS check

On macOS, build the shipping Rust-backed helper and supply an upstream ocproxy executable. The test uses Python 3.11 or later, temporary Unix sockets and a loopback SOCKS listener. It leaves system routes and system proxy settings untouched.

```sh
BUILT_PRODUCTS_DIR=/tmp/simplevpn-ocproxy-check bash Tools/build-event-checker.sh
python3 Tools/OcproxyRelay/check.py /tmp/simplevpn-ocproxy-check/routecheck "$(command -v ocproxy)"
```

The synthetic OpenConnect endpoint implements the script-tun datagram handoff. The actual ocproxy TCP stack completes SOCKS5 CONNECT and receives server payload. The fixture checks both directions of policy enforcement, readiness with an occupied port, and controller exit during authentication and after connection.
