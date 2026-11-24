// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

// routecheck compiles and explains the routing language draft.
// It works offline. VPN names are symbolic, with no access to local profiles.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"

	"pxengine/ocproxyrelay"
	"pxengine/packetrouter"
	"pxengine/routelang"
	"pxengine/routelang/catalog"
)

const maxSourceBytes = 256 << 10

var identifier = regexp.MustCompile("^[a-zA-Z][a-zA-Z0-9_-]{0,79}$")

type action struct {
	Kind string `json:"kind"`
	VPN  string `json:"vpn,omitempty"`
}

type rule struct {
	ID         string `json:"id"`
	Line       int    `json:"line"`
	Prefix     string `json:"prefix,omitempty"`
	SourceKind string `json:"sourceKind,omitempty"`
	Source     string `json:"source,omitempty"`
	Action     action `json:"action"`
}

type program struct {
	Version  int    `json:"version"`
	Rules    []rule `json:"rules"`
	Default  rule   `json:"default"`
	table    packetrouter.DestinationTable
	byID     map[string]int
	bySource map[string]sourceBranch
}

// A source's catchall is required after its more-specific exceptions.
type sourceBranch struct {
	kind   string
	baseID string
	table  packetrouter.DestinationTable
}

type destinationBuilder struct {
	owners map[netip.Prefix]string
	rules  []packetrouter.Rule
}

func (b *destinationBuilder) add(prefix netip.Prefix, id string) error {
	if b.owners == nil {
		b.owners = make(map[netip.Prefix]string)
	}
	// A later rule beneath an earlier ancestor could never win under first
	// match. Reject it so the remaining program exactly lowers to longest prefix.
	for bits := prefix.Bits(); bits >= 0; bits-- {
		ancestor := netip.PrefixFrom(prefix.Addr(), bits).Masked()
		if earlier, exists := b.owners[ancestor]; exists {
			return errors.New("destination already covered by earlier rule " + earlier)
		}
	}
	b.owners[prefix] = id
	b.rules = append(b.rules, packetrouter.Rule{Prefix: prefix, Port: id})
	return nil
}

func destination(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		addr, addrErr := netip.ParseAddr(s)
		if addrErr != nil || addr.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("invalid destination %q", s)
		}
		p = netip.PrefixFrom(addr, addr.BitLen())
	}
	if p.Addr().Is4In6() || p != p.Masked() {
		return netip.Prefix{}, fmt.Errorf("use a canonical IPv4 or IPv6 network for %q", s)
	}
	return p, nil
}

func readSource(r io.Reader) (string, error) {
	data, err := io.ReadAll(io.LimitReader(r, maxSourceBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxSourceBytes {
		return "", errors.New("policy exceeds 256 KiB")
	}
	return string(data), nil
}

func compile(r io.Reader) (*program, error) {
	source, err := readSource(r)
	if err != nil {
		return nil, err
	}
	p := &program{Rules: []rule{}, byID: make(map[string]int), bySource: make(map[string]sourceBranch)}
	var destinations destinationBuilder
	byAlias := make(map[string]*destinationBuilder)
	for lineNumber, line := range policyLines(source) {
		if len(line.words) == 0 {
			continue
		}
		at := func(message string) error { return fmt.Errorf("line %d: %s", lineNumber, message) }
		statement, syntaxErr := parseStatement(line.words)
		if p.Version == 0 {
			if statement.directive != "policy" || syntaxErr != nil {
				return nil, at("expected 'policy 1'")
			}
			p.Version = 1
			continue
		}
		if p.Default.Line != 0 {
			return nil, at("default must be the last statement")
		}
		if syntaxErr != nil {
			return nil, at(syntaxErr.Error())
		}
		if statement.directive == "default" {
			p.Default = rule{ID: "default", Line: lineNumber, Action: statement.action}
			continue
		}
		if statement.directive != "rule" {
			return nil, at("expected 'rule ID ip DESTINATION ACTION'")
		}
		id := statement.ruleID
		if _, exists := p.byID[id]; exists {
			return nil, at("duplicate rule ID " + id)
		}
		if len(p.Rules) == 4096 {
			return nil, at("policy exceeds 4096 rules")
		}
		current := rule{ID: id, Line: lineNumber, SourceKind: statement.sourceKind, Source: statement.source, Action: statement.action}
		if statement.prefix.IsValid() {
			current.Prefix = statement.prefix.String()
		}
		if statement.source != "" {
			if len(destinations.rules) != 0 {
				return nil, at("source and destination rules require separate capture modes")
			}
			alias := statement.source
			branch := p.bySource[alias]
			if branch.kind != "" && branch.kind != statement.sourceKind {
				return nil, at("duplicate source alias across app and process rules: " + alias)
			}
			if branch.baseID != "" {
				return nil, at("source already covered by earlier rule " + branch.baseID)
			}
			branch.kind = statement.sourceKind
			if statement.prefix.IsValid() {
				builder := byAlias[alias]
				if builder == nil {
					builder = &destinationBuilder{}
					byAlias[alias] = builder
				}
				if err := builder.add(statement.prefix, id); err != nil {
					return nil, at(err.Error())
				}
			} else {
				branch.baseID = id
			}
			p.bySource[alias] = branch
		} else {
			if len(p.bySource) != 0 {
				return nil, at("source and destination rules require separate capture modes")
			}
			if err := destinations.add(statement.prefix, id); err != nil {
				return nil, at(err.Error())
			}
		}
		p.byID[id] = len(p.Rules)
		p.Rules = append(p.Rules, current)
	}
	if p.Default.Line == 0 {
		return nil, errors.New("policy requires a final default action")
	}
	if len(p.bySource) != 0 && p.Default.Action.Kind != "drop" {
		return nil, errors.New("source policies require 'default drop' for unattributed traffic")
	}
	for _, rule := range p.Rules {
		builder := byAlias[rule.Source]
		if builder == nil {
			continue
		}
		branch := p.bySource[rule.Source]
		if branch.baseID == "" {
			return nil, fmt.Errorf("line %d: source %s requires a catchall after its IP rules", rule.Line, rule.Source)
		}
		branch.table = packetrouter.CompileDestinations(builder.rules)
		p.bySource[rule.Source] = branch
		delete(byAlias, rule.Source)
	}
	p.table = packetrouter.CompileDestinations(destinations.rules)
	return p, nil
}

func (p *program) lookup(addr netip.Addr) rule {
	if hit, ok := p.table.Lookup(addr); ok {
		return p.Rules[p.byID[hit.Port]]
	}
	return p.Default
}

func run(args []string) error {
	if len(args) > 0 && (args[0] == "--ocproxy-supervise" || args[0] == "--ocproxy-attach") {
		return ocproxyrelay.Run(args)
	}
	return runCommand(args, os.Stdin, os.Stdout)
}

type validationReceipt struct {
	Version       int    `json:"version"`
	Adapter       string `json:"adapter"`
	Engine        string `json:"engine"`
	Handlers      int    `json:"handlers"`
	ScalarEvents  int    `json:"scalarEvents"`
	GeneralEvents int    `json:"generalEvents"`
}

func runCommand(args []string, input io.Reader, output io.Writer) error {
	const usage = "usage: routecheck [--app ALIAS | --process ALIAS] POLICY [IP ...] | routecheck --tokens POLICY | routecheck --events HANDLERS | routecheck --events-for ADAPTER HANDLERS | routecheck --check-live-events ADAPTER HANDLERS | routecheck --schema-for ADAPTER | routecheck --emit-handler ADAPTER ID FILE | routecheck --emit-llvm ADAPTER ID FILE | routecheck --adapters (use - for stdin)"
	enc := json.NewEncoder(output)
	if len(args) == 1 && args[0] == "--adapters" {
		return enc.Encode(catalog.Adapters())
	}
	if len(args) == 2 && args[0] == "--schema-for" {
		schema, ok := catalog.LiveForAdapter(args[1])
		if !ok {
			return fmt.Errorf("adapter %q has no live handler schema", args[1])
		}
		return enc.Encode(struct {
			Events   routelang.Schema `json:"events"`
			Builtins []string         `json:"builtins"`
		}{schema, routelang.BuiltinNames()})
	}
	if len(args) == 4 && (args[0] == "--emit-handler" || args[0] == "--emit-llvm") {
		schema, ok := catalog.LiveForAdapter(args[1])
		if !ok {
			return fmt.Errorf("no live schema for %q", args[1])
		}
		if args[3] != "-" {
			f, err := os.Open(args[3])
			if err != nil {
				return err
			}
			defer f.Close()
			input = f
		}
		source, err := readSource(input)
		if err != nil {
			return err
		}
		p, err := routelang.Compile(source, schema, nil)
		if err != nil {
			return err
		}
		image, err := p.HandlerImage(args[2])
		if err != nil {
			return err
		}
		if args[0] == "--emit-llvm" {
			image, err = routelang.LLVM(image)
			if err != nil {
				return err
			}
		}
		_, err = output.Write(image)
		return err
	}
	export := len(args) > 0 && args[0] == "--export-live-event"
	live := len(args) > 0 && args[0] == "--check-live-events"
	var target string
	if export || live || len(args) > 0 && args[0] == "--events-for" {
		if len(args) != 3 {
			return errors.New(usage)
		}
		adapter, ok := catalog.AdapterByID(args[1])
		if !ok {
			return fmt.Errorf("unknown routing adapter %q (list adapters with --adapters)", args[1])
		}
		if !adapter.RichPolicy || export && len(catalog.SSHEvents(adapter.ID)) == 0 {
			return fmt.Errorf("%s has no live session event handler at its %s boundary", adapter.Name, adapter.Boundary)
		}
		target = adapter.ID
		if (live || export) && !packetrouter.NativeRouting {
			return errors.New("the native routing checker is required for live activation")
		}
		args = []string{"--events", args[2]}
	}
	var source, kind string
	if len(args) != 0 && (args[0] == "--app" || args[0] == "--process") {
		if len(args) < 4 || !identifier.MatchString(args[1]) {
			return errors.New(usage)
		}
		kind, source, args = args[0][2:], args[1], args[2:]
	}
	if len(args) == 0 {
		return errors.New(usage)
	}
	events := args[0] == "--events"
	tokens := args[0] == "--tokens"
	if events || tokens {
		if len(args) != 2 {
			return errors.New(usage)
		}
		args = args[1:]
	}
	if args[0] != "-" {
		f, err := os.Open(args[0])
		if err != nil {
			return err
		}
		defer f.Close()
		input = f
	}
	if events {
		source, err := readSource(input)
		if err != nil {
			return err
		}
		if target == "" {
			target = "wireguard-shared"
		}
		if events := catalog.SSHEvents(target); len(events) > 0 {
			if len(source) > 32768 {
				return errors.New("use at most 32 KiB of handler code")
			}
			schema, _ := catalog.LiveForAdapter(target)
			code, err := routelang.Compile(source, schema, nil)
			if err != nil {
				return err
			}
			ids := code.HandlerIDs()
			if len(ids) > 128 {
				return errors.New("choose up to 128 event handlers")
			}
			if live || export {
				image, err := code.ExportReadOnlyEvents(events)
				if err != nil {
					return err
				}
				if export {
					return enc.Encode(image)
				}
				general := 0
				if len(ids) > 0 {
					general = 1
				}
				return enc.Encode(validationReceipt{1, target, "rust-aot", len(ids), 0, general})
			}
			return enc.Encode(ids)
		}
		p, err := packetrouter.CompileAdapterEvents(target, source)
		if err != nil {
			return err
		}
		defer p.Close()
		counts := p.InspectionCounters()
		if live {
			scalar, general := p.NativeEventCounts()
			return enc.Encode(validationReceipt{1, target, "rust-aot", len(counts), scalar, general})
		}
		return enc.Encode(counts)
	}
	if tokens {
		source, err := readSource(input)
		if err != nil {
			return err
		}
		return enc.Encode(highlight(source))
	}
	p, err := compile(input)
	if err != nil {
		return err
	}
	if len(args) == 1 {
		enc.SetIndent("", "  ")
		return enc.Encode(p)
	}
	for _, s := range args[1:] {
		addr, err := netip.ParseAddr(s)
		if err != nil || addr.Is4In6() || addr.Zone() != "" {
			return fmt.Errorf("invalid test IP %q", s)
		}
		hit := p.lookup(addr)
		if branch, ok := p.bySource[source]; ok && branch.kind == kind {
			id := branch.baseID
			if override, found := branch.table.Lookup(addr); found {
				id = override.Port
			}
			hit = p.Rules[p.byID[id]]
		}
		if err := enc.Encode(struct {
			Destination string `json:"destination"`
			Rule        rule   `json:"rule"`
		}{addr.String(), hit}); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
