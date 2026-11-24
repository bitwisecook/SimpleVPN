#!/bin/bash
# Copyright 2026 James Deucker (bitwisecook)
# SPDX-License-Identifier: GPL-3.0-only
set -euo pipefail

tool_dir="$(cd "$(dirname "$0")" && pwd)"
project_dir="$(cd "$tool_dir/../.." && pwd)"
module_dir="$project_dir/Vendor/proxy-engine/src"
app="$project_dir/build/routing-editor/Routing Editor.app"
contents="$app/Contents"

mkdir -p "$contents/MacOS" "$contents/Helpers" "$contents/Resources"
go -C "$module_dir" build -trimpath -o "$contents/Helpers/routecheck" ./cmd/routecheck
xcrun swiftc -swift-version 6 -warnings-as-errors \
    -module-cache-path "$project_dir/build/routing-editor/ModuleCache" \
    "$project_dir/SimpleVPN/UI/Components/ConfigSyntaxColors.swift" \
    "$tool_dir/main.swift" -o "$contents/MacOS/RoutingEditor"
cp "$tool_dir/Info.plist" "$contents/Info.plist"
cp "$module_dir/cmd/routecheck/testdata/two-vpns.route" "$contents/Resources/"
codesign --force --sign - "$contents/Helpers/routecheck"
codesign --force --sign - "$app"
codesign --verify --deep --strict "$app"
printf '%s\n' "$app"
