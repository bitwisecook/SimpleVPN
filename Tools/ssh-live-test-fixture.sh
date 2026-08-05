#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
#
# ssh-live-test-fixture.sh — lay down the keys and sshd_config that
# SimpleVPNTests/ControlPlane/SSHLiveIntegrationTests.swift needs to talk to a
# REAL SSH server. Without this fixture every live test skips (which is the
# normal state of a CI run); with it they connect, authenticate, forward and
# measure.
#
# NO PRIVILEGE IS NEEDED. /usr/sbin/sshd runs perfectly well as an ordinary user
# on a high port bound to loopback, with its own host key and authorized_keys —
# so a developer machine can prove the libssh event loop against the real thing.
# The tests START AND STOP THEIR OWN sshd from this fixture (one per test, on a
# free port), so nothing is left listening afterwards and no daemon has to be
# babysat between runs.
#
# Usage:
#   ./Tools/ssh-live-test-fixture.sh [dir]        # create/refresh (default /tmp/simplevpn-ssh-live)
#   ./Tools/ssh-live-test-fixture.sh --clean [dir]
#
# The live tests are OPT-IN: they look ONLY at $SIMPLEVPN_SSH_TEST_DIR and skip when it
# is unset. Creating the fixture is therefore not enough to run them — and deliberately
# so, because a fixture left in /tmp used to enrol every later `xcodebuild test` into
# twelve real sshd handshakes and made full runs unreliable.
# Under `xcodebuild test` the environment reaches the test runner prefixed:
#   TEST_RUNNER_SIMPLEVPN_SSH_TEST_DIR=/path/to/fixture xcodebuild … test
#
set -euo pipefail

clean=0
if [[ "${1:-}" == "--clean" ]]; then clean=1; shift; fi
dir="${1:-${SIMPLEVPN_SSH_TEST_DIR:-/tmp/simplevpn-ssh-live}}"

if (( clean )); then
  rm -rf "$dir"
  echo "removed $dir"
  exit 0
fi

mkdir -p "$dir"
# sshd refuses to use a host key (and OpenSSH refuses a client key) whose
# permissions are loose. StrictModes is off below, but the key files themselves
# are still checked.
chmod 700 "$dir"
cd "$dir"

[[ -f hostkey   ]] || ssh-keygen -q -t ed25519 -f hostkey   -N '' -C 'simplevpn-live-test-host'
[[ -f clientkey ]] || ssh-keygen -q -t ed25519 -f clientkey -N '' -C 'simplevpn-live-test-client'
# A SECOND host key, never served by anything: the wrong-pin test needs a
# fingerprint that is real, well-formed and NOT this server's.
[[ -f otherkey  ]] || ssh-keygen -q -t ed25519 -f otherkey  -N '' -C 'simplevpn-live-test-other'
# An encrypted client key, so the passphrase path is exercised too.
[[ -f lockedkey ]] || ssh-keygen -q -t ed25519 -f lockedkey -N 'correct horse' -C 'simplevpn-live-test-locked'

cat clientkey.pub lockedkey.pub > authorized_keys
chmod 600 hostkey clientkey otherkey lockedkey authorized_keys

# The tests always override Port on the command line (-o Port=N) with a free one,
# so the value here is only a placeholder.
cat > sshd_config <<EOF
Port 22022
ListenAddress 127.0.0.1
HostKey $dir/hostkey
AuthorizedKeysFile $dir/authorized_keys
PidFile $dir/sshd.pid
# The fixture lives in a world-readable parent (/tmp), which StrictModes rejects.
StrictModes no
UsePAM no
# Only publickey: a live test must never be able to succeed by falling back to
# something the app would not have chosen.
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
GSSAPIAuthentication no
# direct-tcpip is the whole point — the SSH Network Tunnel dials one channel per
# flow, and the app engine's SOCKS/-L paths use the same channel type.
AllowTcpForwarding yes
PermitOpen any
GatewayPorts no
PermitTunnel no
# DEBUG2 so the kex line naming the negotiated COMPRESSION is in the log; the
# compression test reads it back (libssh exposes no compression getter).
LogLevel DEBUG2
Subsystem sftp internal-sftp
EOF

# The reference fingerprint, in ssh-keygen's own words. The test compares what
# SSHBridge reports against THIS, so a normalisation bug in either can't hide.
ssh-keygen -lf hostkey.pub > hostkey.fp

echo "fixture ready: $dir"
sed -n 's/^/  /p' hostkey.fp
echo "  login user: $(id -un)"
echo
echo "run the live tests with:"
echo "  TEST_RUNNER_SIMPLEVPN_SSH_TEST_DIR=$dir xcodebuild -project SimpleVPN.xcodeproj \\"
echo "    -scheme SimpleVPN -destination 'platform=macOS' test -only-testing:SimpleVPNTests"
