# Embedded IPsec engine

Run `Tools/build-strongswan.sh` on arm64 macOS. It builds the static packet-flow library, installs its headers under `Vendor/strongswan-include`, and runs local peer tests. Setting `IPSEC_UDP_PEER_TEST=1` also runs the native UDP tests on loopback and exchanges data through two simultaneous member workers with identical negotiated routes. The fixtures use synthetic identities, temporary certificate anchors and private socketpairs. The trust tests require access to the macOS trust service.

## Dependencies

- strongSwan 6.1.0 supplies IKE, peer authentication, CHILD_SA negotiation, ESP and replay protection. The build pins the release tarball SHA-256. The release signature was verified with Andreas Steffen's OpenPGP fingerprint `948F 158A 4E76 A27B F3D0 7532 DF42 C170 B34D BA77`. [Upstream releases](https://download.strongswan.org/)
- lwIP 2.2.1 supplies the L2TPv2 client, PPP, MSCHAPv2, LCP and IPCP. The build pins the upstream commit and SHA-256 of its Git archive. Only the L2TP backend starts its event loop. It uses bounded datagram queues and wakes for packet arrival, shutdown and protocol deadlines. [Upstream source](https://github.com/lwip-tcpip/lwip/tree/77dcd25a72509eb83f72b033d219b1d40cd8eb95)
- The IKE crypto plugin links the project's pinned OpenSSL library. License notices for strongSwan, lwIP and the embedded PPP code ship under `SimpleVPN/Resources/Licenses`.

For an offline rebuild, set `STRONGSWAN_TARBALL` to the pinned upstream tarball and `LWIP_CHECKOUT` to a local checkout containing the pinned commit. `STRONGSWAN_BUILD_DIR` selects the extraction and intermediate-object directory. Rebuilding with the same compiler, SDK, source inputs and target gives a deterministic archive.

## Packet and credential boundaries

| Mode | Supported gateway and sign-in |
| --- | --- |
| IKEv2 | Exact IKE identities and a shared secret, or a verified gateway certificate and EAP-MSCHAPv2. |
| IKEv1 | Main Mode and a shared secret, with optional XAuth username/password. |
| L2TP/IPsec | IPv4 IKEv1 Main Mode, exact IDs, shared secret, ESP transport over UDP, UDP/1701 at both L2TP endpoints, and verified MSCHAPv2 sign-in. PPP credentials use 1–255 printable ASCII bytes. IPCP supplies the IPv4 address and optional DNS. LCP constrains the effective MTU. |

The public C API handles raw IP and synchronous borrowed callbacks. The provider sets its networking state after the required address, traffic selectors and authentication are available. L2TP has a separate PPP readiness gate. The negotiated IPsec transport policy admits only IPv4 host selectors on UDP/1701. ESP authenticity and replay checks precede L2TP processing.

Each virtual IPsec member uses its own signed helper process, preserving private SA databases and overlapping selectors. The parent verifies the suspended child before writing options or credentials. Control and packet traffic use separate inherited Unix socketpairs. Every physical UDP socket and source-address lookup is bound to the selected interface. Closing the reliable control channel tears down the member. The signed-fixture test uses a separate signing requirement compiled only into its test driver.
