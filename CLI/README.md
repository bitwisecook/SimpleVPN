# CLI — future `simplevpn` command-line tool (nothing here yet)

A future macOS command-line target (`simplevpn`) for scripting and headless boxes:
`simplevpn connect <name>`, `status --json`, `probe <host>`, diagnostics capture.

Ground rules when this lands:

- New target in `project.yml`, compiling `Shared/` for the app↔extension contract
  types; talks to the running app/extension (XPC or the App-Group control channel) —
  it must NOT embed a second control plane.
- Stable setting ids (`OpenVPNSettingDescriptors`, `EngineSettings` specs) are the
  CLI's flag namespace — the descriptor registry is already the single source of
  truth for id → setting.
- Respects `MDM/ManagedPolicy` exactly like the UI: locked is locked.
- `--json` output everywhere; humans get tables, scripts get JSON.
