# Routing language server

The macOS app launches this local server when a routing source editor opens. The same server works with editors that support LSP over standard input and output.

Build from this directory with `cargo build --release --locked --offline`. Run `routing-lsp --stdio --adapter wireguard`. Place the matching `routecheck` executable alongside it or pass its path with `--routecheck`. The signed app includes both binaries in `Contents/Helpers`.

The server uses the routing compiler’s syntax tree, the adapter’s event schema and the checker’s diagnostics. Each document is limited to 32 KiB of UTF-8 source. Positions and incremental edit ranges use LSP UTF-16 coordinates. Source stays in memory and reaches the checker through a pipe.

Standard methods include diagnostics, completion, hover and document symbols. Select an adapter globally with `--adapter` or `initializationOptions.adapter`, or per document with `params.adapter` on open.

The server exposes four editor requests. All take a standard `textDocument` identifier.

- `simplevpn/syntaxTree` returns declarations, types, expressions and statement ranges.
- `simplevpn/concreteSyntax` returns lossless tokens with UTF-8 byte ranges. Send its `nextToken` as `firstToken` for the next page.
- `simplevpn/eventDiagram` returns adapter events and source ranges of their existing handlers.
- `simplevpn/addHandler` takes `event` and the current document `version`. It returns a text edit and the new handler’s selection range. The editor applies the edit through its usual undo system.

The nested `simplevpn/syntaxTree` preview is limited to 1,200 nodes. For the complete tree, send `firstNode: 0` on the same method and follow `nextNode` until it is null. Each page contains at most 512 nodes with preorder indices, parent indices and UTF-8 byte ranges. Use pages from the same document version.
