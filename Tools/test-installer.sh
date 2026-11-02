#!/usr/bin/env bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
# Exercise installer decisions and real filesystem transactions without starting a VPN app.
set -euo pipefail
cd "$(dirname "$0")/.."
TEST_PACKAGE="$(mktemp -d "${TMPDIR:-/tmp}/SimpleVPN-installer-tests.XXXXXX")"
trap 'rm -rf "$TEST_PACKAGE"' EXIT
mkdir -p "$TEST_PACKAGE/Sources/InstallationSupport" "$TEST_PACKAGE/Tests/InstallationTests"
cp SimpleVPN/App/Installation/InstallationModel.swift SimpleVPN/App/Installation/InstallationWorker.swift SimpleVPN/App/Installation/InstallationRunningApps.swift "$TEST_PACKAGE/Sources/InstallationSupport/"
cp SimpleVPNTests/App/InstallationTests.swift "$TEST_PACKAGE/Tests/InstallationTests/"
cat > "$TEST_PACKAGE/Package.swift" <<'SWIFT'
// swift-tools-version: 6.2
import PackageDescription
let package = Package(name: "InstallationSupport", platforms: [.macOS("26.0")], targets: [
    .target(name: "InstallationSupport", swiftSettings: [.unsafeFlags(["-warnings-as-errors", "-default-isolation", "MainActor"])]),
    .testTarget(name: "InstallationTests", dependencies: ["InstallationSupport"], swiftSettings: [.define("INSTALLATION_STANDALONE"), .unsafeFlags(["-warnings-as-errors"])])
])
SWIFT
CLANG_MODULE_CACHE_PATH="$TEST_PACKAGE/ModuleCache" swift test --package-path "$TEST_PACKAGE" --scratch-path "$PWD/build/installer-tests" --disable-sandbox
python3 Tools/generate-installer-icon.py --check
