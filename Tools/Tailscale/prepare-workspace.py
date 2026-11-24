#!/usr/bin/env python3
"""Apply the per-node socket binding patch to a private copy of the pinned Go module files."""
from pathlib import Path
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

out = Path(sys.argv[1]).resolve()
patch = Path(__file__).with_name("member-underlay.patch")
module = json.loads(subprocess.check_output(["go", "mod", "download", "-json", "tailscale.com"], env={**os.environ, "GOWORK": "off"}))
if module.get("Version") != "v1.104.7" or not module.get("Dir"):
    sys.exit("The Tailscale underlay patch requires a review against the selected module.")
source = Path(module["Dir"])
files = ["net/netmon/netmon.go", "net/netns/netns.go", "net/netns/netns_darwin.go"]
engine = Path.cwd().resolve()
identity = hashlib.sha256(b"workspace-v1" + str(engine).encode() + patch.read_bytes() + module["Sum"].encode()).hexdigest()
out.mkdir(parents=True, exist_ok=True)
dest = out / identity
if not dest.exists():
    with tempfile.TemporaryDirectory(dir=out) as root:
        staged = Path(root) / "sources"
        # Go forbids overlays in GOMODCACHE. Construct an immutable local module
        # replacement. Patched files must never share an inode with the cache.
        def copy_source(src, dst):
            if Path(src).relative_to(source).as_posix() in files:
                return shutil.copyfile(src, dst)
            try:
                os.link(src, dst)
            except OSError:
                shutil.copyfile(src, dst)

        shutil.copytree(source, staged, copy_function=copy_source)
        for name in files:
            (staged / name).parent.chmod(0o755)
        staged.chmod(0o755)
        subprocess.run(["patch", "--batch", "-s", "-p1", "-i", str(patch.resolve())], cwd=staged, check=True)
        workspace = "go 1.27.4\n\nuse " + json.dumps(str(engine)) + "\nreplace tailscale.com => " + json.dumps(str(dest)) + "\n"
        (staged / "go.work").write_text(workspace)
        try:
            os.rename(staged, dest)
        except OSError:
            if not (dest / "go.work").is_file():
                raise
print(dest / "go.work")
