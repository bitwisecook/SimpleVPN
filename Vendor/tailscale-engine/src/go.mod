module tsengine

go 1.27.1

replace pxengine => ../../proxy-engine/src

require (
	// Match tailscale.com's stable release: newer wireguard-go revisions change
	// tun.Device.Read and do not compile with Tailscale 1.102.x (Docs/Drift.md §14).
	github.com/tailscale/wireguard-go v0.0.0-20260715223240-2e01ba5b00f0
	golang.org/x/sys v0.48.0
	// The proxy-tunnel engine (SimpleVPN's Proxy Tunnel VPN kind) is folded into
	// THIS Go c-archive rather than its own: two Go c-archives cannot link into one
	// binary (duplicate runtime symbols), and PacketTunnel already links this one.
	// main.go blank-imports it so its //export symbols land here. pxengine is a
	// local module (its own pinned go.mod/tests/header); the replace keeps it out
	// of the module proxy. It shares this build's gVisor pin.
	pxengine v0.0.0
	tailscale.com v1.102.5
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/alexbrainman/sspi v0.0.0-20250919150558-7d374ff0d59e // indirect
	github.com/aws/aws-sdk-go-v2 v1.47.1 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.33.6 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.20.6 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.20.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.4 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.5.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.14.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.10.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssm v1.79.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.38.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.43.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.51.1 // indirect
	github.com/aws/smithy-go v1.28.2 // indirect
	github.com/coder/websocket v1.8.15 // indirect
	github.com/coreos/go-iptables v0.8.0 // indirect
	github.com/creachadair/msync v0.10.1 // indirect
	github.com/dblohm7/wingoes v0.0.0-20260526185140-fb298caac7ca // indirect
	github.com/digitalocean/go-smbios v0.0.0-20180907143718-390a4f403a8e // indirect
	github.com/fxamacker/cbor/v2 v2.9.4 // indirect
	github.com/gaissmai/bart v0.30.0 // indirect
	github.com/go-json-experiment/json v0.0.0-20260820222146-c27c302e5fc3 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/nftables v0.3.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/illarion/gonotify/v3 v3.0.2 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20260901064844-234b97448fae // indirect
	github.com/jsimonetti/rtnetlink v1.4.2 // indirect
	github.com/klauspost/compress v1.20.1 // indirect
	github.com/kortschak/wol v0.0.0-20200729010619-da482cc4850a // indirect
	github.com/mdlayher/genetlink v1.4.0 // indirect
	github.com/mdlayher/netlink v1.11.2 // indirect
	github.com/mdlayher/sdnotify v1.0.0 // indirect
	github.com/mdlayher/socket v0.7.0 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/pierrec/lz4/v4 v4.1.31 // indirect
	github.com/pires/go-proxyproto v0.15.0 // indirect
	github.com/safchain/ethtool v0.7.0 // indirect
	github.com/tailscale/certstore v0.1.1-0.20260409135935-3638fb84b77d // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/tailscale/hujson v0.0.0-20260727124030-b80ff77dac4f // indirect
	github.com/tailscale/netlink v1.1.1-0.20240822203006-4d49adab4de7 // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/tailscale/web-client-prebuilt v0.0.0-20260917222731-e0ed2d0d0fea // indirect
	github.com/u-root/uio v0.0.0-20240224005618-d2acac8f3701 // indirect
	github.com/vishvananda/netns v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20260823151212-3075585bcbeb // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/exp v0.0.0-20260908205506-85c1c2202aba // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/term v0.46.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/time v0.16.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	golang.zx2c4.com/wireguard/windows v1.1.1 // indirect
	gvisor.dev/gvisor v0.0.0-20260930000514-4c7ae5e19a78 // indirect
)
