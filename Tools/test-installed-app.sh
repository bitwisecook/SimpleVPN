#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Run installed-app checks without rebuilding/replacing the notarized app.
# First build the test runner with xcodebuild build-for-testing; pass its .xctestrun.
# Xcode's default target path resolves to DerivedData even with a bundleIdentifier.
set -euo pipefail
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
  echo "usage: $0 <build-for-testing .xctestrun>" >&2
  exit 64
fi
if [ ! -d /Applications/SimpleVPN.app ]; then
  echo "Install a notarized app with Tools/build-notarize-install.sh first." >&2
  exit 1
fi
TEST_CONFIG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/simplevpn-installed-tests.XXXXXX")"
trap 'rm -rf "$TEST_CONFIG_DIR"' EXIT
python3 - "$1" "$TEST_CONFIG_DIR/Installed.xctestrun" <<'PY'
import pathlib
import plistlib
import sys

source = pathlib.Path(sys.argv[1]).resolve()
data = plistlib.loads(source.read_bytes())
# This script intentionally rejects unknown formats rather than silently running
# the default development app when Xcode changes its test configuration schema.
if data.get('__xctestrun_metadata__', {}).get('FormatVersion') != 1:
    raise SystemExit('Unsupported .xctestrun format; explicitly update the installed target mapping.')
target = data['SimpleVPNUITests']
if not target.get('IsUITestBundle') or 'UITargetAppPath' not in target:
    raise SystemExit('Missing UI target app configuration.')

def absolute_test_root(value):
    if isinstance(value, str):
        return value.replace('__TESTROOT__', str(source.parent))
    if isinstance(value, dict):
        return {k: absolute_test_root(v) for k, v in value.items()}
    if isinstance(value, list):
        return [absolute_test_root(v) for v in value]
    return value

target = absolute_test_root(target)
target['UITargetAppPath'] = '/Applications/SimpleVPN.app'
target.setdefault('EnvironmentVariables', {})['SIMPLEVPN_INSTALLED_UI_TEST_TARGET'] = target['UITargetAppPath']
configured = {'SimpleVPNUITests': target, '__xctestrun_metadata__': data['__xctestrun_metadata__']}
pathlib.Path(sys.argv[2]).write_bytes(plistlib.dumps(configured))
print('UI target app: ' + target['UITargetAppPath'])
PY
xcodebuild test-without-building -xctestrun "$TEST_CONFIG_DIR/Installed.xctestrun" \
  -destination 'platform=macOS,arch=arm64' -only-testing:SimpleVPNUITests/InstalledExtensionTests
# The UI runner's sandbox refuses systemextensionsctl. Query registration here,
# without weakening that sandbox or pretending About supplies live provider IPC.
python3 - <<'PY'
import pathlib
import plistlib
import subprocess
import time

identifier = 'com.bragi0.SimpleVPN.PacketTunnel'
extension = pathlib.Path('/Applications/SimpleVPN.app/Contents/Library/SystemExtensions') / (identifier + '.systemextension')
info = plistlib.loads((extension / 'Contents/Info.plist').read_bytes())
expected = '(' + info['CFBundleShortVersionString'] + '/' + info['CFBundleVersion'] + ')'
deadline = time.monotonic() + 30
while True:
    result = subprocess.run(['/usr/bin/systemextensionsctl', 'list'], check=True,
                            capture_output=True, text=True, timeout=5)
    for line in result.stdout.splitlines():
        columns = line.split()
        if (len(columns) >= 6 and columns[:2] == ['*', '*']
                and columns[3:5] == [identifier, expected]
                and '[activated enabled]' in line):
            print('Enabled extension matches installed build: ' + identifier + ' ' + expected)
            raise SystemExit(0)
    if time.monotonic() >= deadline:
        raise SystemExit('Enabled extension did not match ' + expected + ':\n' + result.stdout)
    time.sleep(0.25)
PY
