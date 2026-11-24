#!/usr/bin/env python3
"""Refresh just the self-contained VM in an existing routing atlas."""
import base64
import gzip
import os
from pathlib import Path
import subprocess
import tempfile

root = Path(__file__).resolve().parents[2]
atlas = root / 'Docs/RoutingAtlas.html'
start = '<!-- compiled routing runtime -->'
end = '<!-- end compiled routing runtime -->'
html = atlas.read_text()
before, sep, rest = html.partition(start)
if not sep or end not in rest:
    raise SystemExit('Missing routing runtime markers in the atlas.')
after = rest.split(end, 1)[1]
env = dict(os.environ, GOOS='js', GOARCH='wasm', CGO_ENABLED='0')
with tempfile.TemporaryDirectory() as tmp:
    wasm = Path(tmp) / 'routelab.wasm'
    subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-ldflags=-s -w', '-o', str(wasm), './cmd/routelab'],
                   cwd=root/'Vendor/proxy-engine/src', env=env, check=True)
    payload = base64.b64encode(gzip.compress(wasm.read_bytes(), compresslevel=9, mtime=0)).decode('ascii')
goroot = Path(subprocess.check_output(['go', 'env', 'GOROOT'], text=True).strip())
bootstrap = (goroot / 'lib/wasm/wasm_exec.js').read_text()
# Keep the upstream license and toolchain support code with the binary.
license_path = goroot / 'LICENSE'
if not license_path.is_file() and goroot.name == 'libexec':
    license_path = goroot.parent / 'LICENSE'
license_text = license_path.read_text()
body = '<script type="text/plain" id="go-license">'+license_text+'</script>\n'
body += '<script>'+bootstrap+'</script>\n<script type="application/octet-stream" id="routing-wasm">'+payload+'</script>'
atlas.write_text(before + start + body + end + after)
