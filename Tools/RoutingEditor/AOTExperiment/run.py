#!/usr/bin/env python3
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only

import json
import os
from pathlib import Path
import random
import shutil
import statistics
import subprocess
import tempfile

SOURCE = Path(__file__).resolve().parent
MODULE = SOURCE.parents[2] / "Vendor/proxy-engine/src"


def run(*args, cwd, env, capture=False):
    result = subprocess.run(args, cwd=cwd, env=env, text=True,
                            stdout=subprocess.PIPE if capture else None, check=True)
    return result.stdout


def main():
    with tempfile.TemporaryDirectory(prefix="simplevpn-aot-") as temp:
        out = Path(temp)
        env = dict(os.environ, GOPROXY="off", GOTOOLCHAIN="local", GOWORK="off",
                   AOT_SOURCE=str(SOURCE), AOT_OUTPUT=str(out))
        overlay = out / "overlay.json"
        test_path = MODULE / "routelang/aot_experiment_overlay_test.go"
        if test_path.exists():
            raise RuntimeError(f"Overlay path is occupied: {test_path}")
        overlay.write_text(json.dumps({"Replace": {str(test_path): str(SOURCE / "lower_test.go")}}))

        def build(*args):
            run(*args, cwd=out, env=env)

        go_test = ["go", "test", "-overlay", overlay, "-count=1"]
        run(*go_test, "-run", "^TestAOTExperiment$", "./routelang", cwd=MODULE, env=env)
        build("clang", "-O3", "-c", SOURCE / "driver.c", "-o", "driver.o")
        names = ["rule", "shortcircuit"]
        for name in names:
            build("clang", "-O3", "driver.o", f"{name}.c", "-o", name)

        if shutil.which("swiftc"):
            build("swiftc", "-O", "-parse-as-library", "-module-cache-path", out / "swift-cache",
                  "-emit-object", SOURCE / "rule.swift", "-o", "swift.o")
            build("swiftc", "driver.o", "swift.o", "-o", "swift")
            names.append("swift")
        if shutil.which("rustc"):
            build("rustc", "--edition=2024", "--crate-type=lib", "-C", "opt-level=3",
                  "-C", "panic=abort", "--emit=obj", SOURCE / "rule.rs", "-o", "rust.o")
            build("clang", "driver.o", "rust.o", "-o", "rust")
            names.append("rust")

        trials = {name: [] for name in names}
        for round_id in range(9):
            order = list(names)
            random.Random(305 + round_id).shuffle(order)
            for name in order:
                ns = float(run(out / name, cwd=out, env=env, capture=True))
                trials[name].append(ns)
        print("Verified 16,864 oracle cases and 8,192 mixed events per target.")
        for name, ns in trials.items():
            print(f"{name:14} {statistics.median(ns):6.2f} ns/event median "
                  f"({min(ns):.2f}–{max(ns):.2f}, C caller)")
        print("Existing VM benchmark and mixed-corpus VM benchmark", flush=True)
        run("go", "test", "-overlay", overlay, "-run", "^$",
            "-bench", "^Benchmark(CompiledDispatch|AOTExperimentMixedVM)$",
            "-benchtime=400ms", "-count=5", "./routelang", cwd=MODULE, env=env)


if __name__ == "__main__":
    main()
