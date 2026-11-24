// swift-tools-version: 6.0
// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import PackageDescription

let package = Package(
    name: "SSHProxyCodec",
    platforms: [.macOS(.v14)],
    products: [.library(name: "SSHProxyCodec", targets: ["SSHProxyCodec"])],
    dependencies: [.package(url: "https://github.com/apple/swift-nio.git", exact: "2.105.1")],
    targets: [.target(name: "SSHProxyCodec", dependencies: [.product(name: "NIOCore", package: "swift-nio")])]
)
