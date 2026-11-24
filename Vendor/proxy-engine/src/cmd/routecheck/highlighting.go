// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"errors"
	"iter"
	"net/netip"
	"strings"
)

// Offsets and lengths count UTF-8 bytes in the unmodified source.
type highlightToken struct {
	Offset int    `json:"offset"`
	Length int    `json:"length"`
	Kind   string `json:"kind"`
}

type sourceWord struct {
	text  string
	start int
	kind  string
}

type sourceLine struct {
	words   []sourceWord
	comment sourceWord
}

func policyLines(source string) iter.Seq2[int, sourceLine] {
	return func(yield func(int, sourceLine) bool) {
		offset := 0
		lineNumber := 1
		for raw := range strings.SplitSeq(source, "\n") {
			text := strings.TrimSuffix(raw, "\r")
			body, _, found := strings.Cut(text, "#")
			line := sourceLine{}
			if found {
				line.comment = sourceWord{text: text[len(body):], start: offset + len(body), kind: "comment"}
			}
			cursor := 0
			for word := range strings.FieldsSeq(body) {
				cursor += strings.Index(body[cursor:], word)
				line.words = append(line.words, sourceWord{text: word, start: offset + cursor, kind: "error"})
				cursor += len(word)
			}
			if !yield(lineNumber, line) {
				return
			}
			offset += len(raw) + 1
			lineNumber++
		}
	}
}

type statement struct {
	directive  string
	ruleID     string
	sourceKind string
	source     string
	prefix     netip.Prefix
	action     action
}

func markWord(words []sourceWord, i int, kind, expected string) bool {
	if i >= len(words) || words[i].text != expected {
		return false
	}
	words[i].kind = kind
	return true
}

func actionSyntax(words []sourceWord) (action, error) {
	if markWord(words, 0, "keyword", "drop") && len(words) == 1 {
		return action{Kind: "drop"}, nil
	}
	if markWord(words, 0, "keyword", "via") && len(words) >= 2 && identifier.MatchString(words[1].text) {
		words[1].kind = "vpn"
		if len(words) == 2 {
			return action{Kind: "via", VPN: words[1].text}, nil
		}
	}
	return action{}, errors.New("expected 'via VPN' or 'drop'")
}

// Classify every present field even when another field is still being edited.
// Compilation uses the same statement parser and also checks whole-policy semantics.
func parseStatement(words []sourceWord) (statement, error) {
	s := statement{directive: words[0].text}
	switch s.directive {
	case "policy":
		words[0].kind = "keyword"
		if !markWord(words, 1, "number", "1") || len(words) != 2 {
			return s, errors.New("expected 'policy 1'")
		}
	case "default":
		words[0].kind = "keyword"
		a, err := actionSyntax(words[1:])
		s.action = a
		return s, err
	case "rule":
		words[0].kind = "keyword"
		idOK := len(words) > 1 && identifier.MatchString(words[1].text) && words[1].text != "default"
		if idOK {
			s.ruleID = words[1].text
			words[1].kind = "rule"
		}
		if markWord(words, 2, "keyword", "app") || markWord(words, 2, "keyword", "process") {
			s.sourceKind = words[2].text
			aliasAt := 3
			if s.sourceKind == "app" {
				if !markWord(words, 3, "keyword", "signed") {
					return s, errors.New("expected 'app signed ALIAS'")
				}
				aliasAt++
			}
			if len(words) <= aliasAt || !identifier.MatchString(words[aliasAt].text) {
				return s, errors.New("expected a symbolic source alias")
			}
			s.source = words[aliasAt].text
			words[aliasAt].kind = "source"
			actionAt := aliasAt + 1
			if markWord(words, actionAt, "keyword", "ip") {
				if actionAt+1 >= len(words) {
					return s, errors.New("expected an IP destination after 'ip'")
				}
				prefix, err := destination(words[actionAt+1].text)
				if err != nil {
					return s, err
				}
				words[actionAt+1].kind = "network"
				s.prefix = prefix
				actionAt += 2
			}
			a, err := actionSyntax(words[actionAt:])
			s.action = a
			if !idOK {
				return s, errors.New("invalid or reserved rule ID")
			}
			return s, err
		}
		hasIP := markWord(words, 2, "keyword", "ip")
		var networkErr, actionErr error
		if len(words) > 3 {
			s.prefix, networkErr = destination(words[3].text)
			if networkErr == nil {
				words[3].kind = "network"
			}
		}
		if len(words) > 4 {
			s.action, actionErr = actionSyntax(words[4:])
		}
		if !hasIP || len(words) < 5 {
			return s, errors.New("expected 'rule ID ip DESTINATION ACTION'")
		}
		if !idOK {
			return s, errors.New("invalid or reserved rule ID")
		}
		if networkErr != nil {
			return s, networkErr
		}
		return s, actionErr
	default:
		return s, errors.New("expected 'rule ID ip DESTINATION ACTION'")
	}
	return s, nil
}

func highlight(source string) []highlightToken {
	tokens := []highlightToken{}
	for _, line := range policyLines(source) {
		if len(line.words) > 0 {
			_, _ = parseStatement(line.words)
			for _, word := range line.words {
				tokens = append(tokens, highlightToken{word.start, len(word.text), word.kind})
			}
		}
		if c := line.comment; c.text != "" {
			tokens = append(tokens, highlightToken{c.start, len(c.text), c.kind})
		}
	}
	return tokens
}
