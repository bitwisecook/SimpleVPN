# Routing editor for macOS

Open the standalone HTML file to edit typed handlers, inspect their branch traces, and replay process, packet and connection fixtures. The document contains its compiler. After changing the compiler or event catalog, run `python3 Tools/RoutingEditor/embed-routelang.py` and `node Tools/RoutingEditor/check-atlas.mjs` from the project root to rebuild and test the embedded copy. [Routing playground](RoutingAtlas.html#rich-playground)

In the macOS profile and composition event editors, the signed Rust language server supplies adapter-aware completion, hover, diagnostics and document symbols over stdio. The event diagram shows which handlers are attached at each layer. Select a handler to jump to it, or choose an available event to insert a new, uniquely named handler as one undoable edit. Each change carries its document version. The helper starts when an editor needs it.

Open **Custom Routing** and choose **Add Handlers…** or **Edit Handlers…** to use the **Graphical Builder** alongside Source. The railroad shows the selected handler’s statements and branches. Drag a palette block, an existing block or its incoming connector onto a connector to insert or move the block. With the keyboard, select a block and a connector, then choose **Move Here**. Select a block to edit its action or condition, or choose **Show in Source** to reveal the exact text. Source changes update the railroad, and a graphical change is one Undo step. Compact handlers can be inspected in the railroad and edited in Source. The existing validation and save flow applies to the shared draft.

`simplevpn/railroad` returns the adapter’s events and the versioned header, body and condition ranges used by the builder. The editor uses these ranges against the matching source revision for every edit.

An LSP client can request `simplevpn/syntaxTree` for declaration and expression ranges, `simplevpn/eventDiagram` for the adapter’s events, or `simplevpn/addHandler` for a versioned insertion. `simplevpn/concreteSyntax` returns a page of lossless token ranges, including comments and whitespace. Send its `nextToken` value as `firstToken` to read the next page. Concrete syntax uses UTF-8 byte offsets into the versioned source. Selection and editing use LSP UTF-16 positions. To read the entire AST, start with `firstNode: 0` in `simplevpn/syntaxTree` and request `nextNode` until the server returns null. Parent indices and source ranges belong to one document version.

**Design proposal.** The first release of the language tools runs offline. A person can write a policy and find out where it would send traffic before giving it control of a connection. The language specification owns grammar, precedence and failure behavior. The editor uses its parser, validator and evaluator for both visual and source editing. [Routing language](RoutingLanguage.md)

## Run the offline prototype

From the repository directory containing `project.yml`, run the build script with Go 1.27.4 and the macOS Swift toolchain. Double-click **Routing Editor.app** in `build/routing-editor`, or launch it from Terminal.

```sh
Tools/RoutingEditor/build.sh
open "build/routing-editor/Routing Editor.app"
```

The app contains the checker and sample. To open another local draft, pass the checker and source paths to the executable.

```sh
editor="build/routing-editor/Routing Editor.app/Contents"
"$editor/MacOS/RoutingEditor" "$editor/Helpers/routecheck" path/to/draft.route
```

Edit the sample and choose **File → Test Destination** (⌘Return). Its payroll rule sends `10.42.8.19` through the symbolic VPN `finance`. Try `10.42.8.20` to see the broader `office` rule choose `work`, or `192.0.2.1` to see the default drop. The result names the rule and source line. A syntax error appears as text when testing.

This developer tool keeps edits in memory and sends the source to the local checker on standard input. It opens the sample read-only and runs without a VPN or network access. Copy any edits you want to keep before closing. The following sections describe the proposed product UI.

For a source policy, choose **Signed app** or **Running process** beside **Source** and enter an alias used in the draft. **Unknown** tests the policy without attribution. The source picker supplies simulated evidence to the checker. In SimpleVPN, **Route Apps Through This VPN…** lets you select an executable or a specific running process and bind it to an actual WireGuard VPN.

## Where people enter

| Starting point | What the person sees |
| --- | --- |
| One VPN | The connection window keeps its Connect action and status. In the VPN editor, Traffic shows **Send All Traffic** where supported, the routes the VPN offers, and any bypasses. **Test a Destination…** opens Routes with this VPN selected. There is no policy to create before connecting. |
| Multiple VPNs | **Window → Routes** opens the existing route diagram and search. The Default gateway picker identifies which VPN or Direct carries unmatched traffic when the current configuration offers that choice. Select a VPN to inspect its routes, DNS and connection state. |
| A routing question | **Test a Destination…** accepts an IPv4 or IPv6 address. A separate DNS query test accepts a name and identifies the selected resolver. From a traffic-log row, **Explain This Flow** carries the recorded facts into Routes and identifies their source and time. |
| A custom policy | **Edit Routing Policy…** opens an editor for a named policy in Routes. Its title identifies the scope, for example a composition of Work and Lab. A VPN keeps its stable identifier when renamed. A deleted reference is shown as a problem until the person chooses a replacement. |

A local port appears as a local port. A managed, native or unsupported VPN indicates which changes it can accept and why a control is unavailable. A routed connection can have one to sixteen compatible VPNs. The shared editor offers member identity, profile, generation and VPN kind at the packet boundary. Select a member’s own editor to check its adapter-specific events. The proposed policy surface must consult the selected runtime. [Project terminology](../ONTOLOGY.md) · [Implementation and compatibility](NetworkArchitectureReview.md) · [DNS routing](DNSRoutingReview.md)

## Rules and source

Use a resizable native split view. The leading pane lists rules in evaluation order. Selecting a row opens its editable fields. A **Rules / Source** control switches representations and keeps the same selection. The existing route diagram is optional supporting detail. In a narrow window, collapse the inspector and keep the rule list and its selected detail reachable by keyboard.

A row reads as a sentence, for example **Send 10.20.0.0/16 through Work**. **Add Rule** starts with a destination and a choice of eligible VPNs. Show optional conditions, unavailable-VPN behavior and additional actions on disclosure. Expose Move Up and Move Down alongside drag reordering. Keep unmatched traffic visible in a pinned final row. Explicit rules use first match. Show routes learned from a VPN separately with their origin. In a test, a learned candidate can explain why a path is available. Only policy authorization permits its use. Give Direct its own explicit choice and preview which traffic could leave a VPN.

The saved draft is the original source. Each editable row refers to a parsed node and its source range. A structured edit replaces that range in a single undo operation. Preserve comments, whitespace, quoting, unknown constructs and intermediate invalid text. **Show in Source** selects the exact construct. A custom Tcl 9 handler has a named row with **Edit in Source**. Declarative statements compile independently. A parse error that makes a region ambiguous disables structural changes there and links to the diagnostic. Switching views never reformats a file.

## Source editing and highlighting

Use a native multiline plain-text editor with a system monospaced font. Keep ⌘F for Find, ⌘Z for Undo and ⌘S for Save Draft. Escape closes completion or dismisses a test sheet and returns focus to the invoking control. Map lexer byte spans to text-system ranges against the same revision so quoted Unicode VPN names, selection and input-method marked text survive highlighting. Disable smart quotes, automatic substitutions and spelling corrections in source. Return inserts a newline. Tab follows Full Keyboard Access conventions, with explicit Indent and Outdent commands in the menu.

| Source element | Treatment |
| --- | --- |
| Declarations, conditions and actions | Apply a semantic keyword color and medium weight. Preserve spelling and case. |
| VPN references, addresses, prefixes, ports and quoted values | Give references and literals distinct styles. **Reveal Referenced VPN** resolves a reference by identity. Hover information also appears in the inspector. |
| Tcl handlers and comments | Delimit each handler with its event name and matching brace. Tokenize its body as Tcl, including nested substitutions, escapes and quoted text. Comments use a legible secondary foreground. |
| Diagnostics | Underline the exact range and list severity, line, column, explanation and suggested fix in **Problems**. Activating a problem selects it in the editor. Mark warnings with a distinct symbol and text. |

Use semantic system colors with light, dark and Increase Contrast variants. The policy remains legible in monochrome. VoiceOver reads ordinary source text and can navigate a separate rule outline and Problems list. Announce completed validation and its issue count on request, without speaking on every keystroke. Place focus back on the source range after navigating to a problem. Offer the same commands through menus for pointer, keyboard and Voice Control users. “Support keyboard-only navigation with Full Keyboard Access. Avoid overriding system-defined keyboard shortcuts.” [Apple accessibility guidance](https://developer.apple.com/design/human-interface-guidelines/accessibility) · [Project accessibility conventions](Accessibility.md)

## Test, observe and apply

1. **Test the draft.** Enter a destination and optional facts such as transport or port. Show the policy revision, rules considered in order, missing facts, selected VPN or other disposition, and the reason. Selecting a step reveals the corresponding rule. If the question requires unavailable evidence, say what is missing. The offline evaluator reads fixtures or an identified snapshot. It sends no packets and changes no routes.
2. **Explain observed traffic.** Identify the active revision and any rule, translation, DNS source or selected VPN actually recorded by the provider. For older flows pinned to a previous revision, name that revision. If all macOS observed was the shared interface, say so. Losing app or guest identity during address translation leaves that field unknown. **Test Against Draft** reuses the available facts and labels the result as a prediction.
3. **Save Draft** preserves text, including unfinished work. In a future runtime-enabled release, a separate **Review Changes…** shows the active and proposed revisions, affected VPNs and destinations, bypasses, and any reconnect required. **Apply Policy** validates against current capabilities and rejects stale revisions. Keep the last acknowledged revision active on failure. Show applying, acknowledged and independently observed states with their timestamps. Offer a previous revision as a new reviewable draft.

## Delivery and acceptance

| Stage | Acceptance check |
| --- | --- |
| Offline editor | Open and close without changing network settings. Edit one row in a file containing comments and a Tcl handler, undo, and compare the original bytes. Test overlapping explicit rules, an unavailable VPN, unmatched traffic and an IPv6 destination. Test a monochrome session and a keyboard-only journey from an error to the corrected preview. |
| Live explanation | Show a recorded decision beside a clearly labelled draft prediction. Preserve unknown facts. Sample only while a live view is visible, retain bounded history, and stop observation on dismissal. |
| Runtime application | Enable Apply only for capabilities supported end to end. Test a failed apply, concurrent changes, withdrawal of a route and a flow pinned to an earlier revision. Add listeners, application identity, Tcl execution or DNS translation only when the selected runtime can supply and enforce them. |

Use the language parser’s token spans for syntax color and its resolved references for semantic highlighting. Keep this work scoped to open editors. Parse changed text after a short debounce, discard superseded results, and invalidate only affected display ranges. Load Tcl language services when a handler is opened. Opening Routes to inspect a single VPN should require neither script execution nor a background language service. [Policy editor and simulator proposal](PolicyRouting.md#gui-editor) · [Event vocabulary](PolicyEvents.md)

The nested `simplevpn/syntaxTree` preview is limited to 1,200 nodes. For the complete tree, send `firstNode: 0` on the same method and follow `nextNode` until it is null. Each page contains at most 512 nodes with preorder indices, parent indices and UTF-8 byte ranges. Use pages from the same document version.
