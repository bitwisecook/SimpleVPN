// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package catalog

import (
	"errors"
	"strings"

	"pxengine/routelang"
)

// ObservationPlan names the hooks an adapter can derive from one parsed input.
// ExtraFields exposes equivalent, read-only compatibility names. A missing
// field never gains a false, empty or otherwise fabricated value.
type ObservationPlan struct {
	Hooks       []string
	ExtraFields map[string]routelang.Value
}

var protectionNames = [...]struct{ current, legacy string }{
	{"ftp.tls_mode", "ftps.mode"},
	{"ftp.control_encrypted", "ftps.control_encrypted"},
	{"ftp.data_private", "ftps.data_private"},
}

// PlanObservation is for owned endpoint observations. It operates on typed,
// schema-validated fields. A packet adapter does not classify FTP control text.
func PlanObservation(name string, fields map[string]routelang.Value, hasLegacyFTPS bool) (ObservationPlan, error) {
	plan := ObservationPlan{Hooks: []string{name}}
	switch name {
	case "ftp.command.passive":
		return ObservationPlan{}, errors.New("ftp.command.passive is derived; supply a parsed ftp.command observation with PASV or EPSV")
	case "ftp.command", "ftp.reply", "ftp.data_offer":
		if err := checkTLSMode(fields); err != nil {
			return ObservationPlan{}, err
		}
		encrypted := fields["ftp.control_encrypted"]
		for _, key := range []string{"tls.version", "tls.alpn", "tls.peer_verified"} {
			if _, ok := fields[key]; ok && (encrypted.Type() != routelang.TBool || !encrypted.AsBool()) {
				return ObservationPlan{}, errors.New("FTP control TLS session evidence requires ftp.control_encrypted=true")
			}
		}
		if name == "ftp.command" {
			if cmd, ok := fields["ftp.command"]; ok {
				verb := cmd.AsString()
				if len(verb) == 0 || len(verb) > 16 {
					return ObservationPlan{}, errors.New("expected one parsed FTP command verb")
				}
				for i := 0; i < len(verb); i++ {
					c := verb[i]
					if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z') {
						return ObservationPlan{}, errors.New("FTP command must contain only an ASCII verb, without arguments")
					}
				}
				if strings.EqualFold(verb, "PASV") || strings.EqualFold(verb, "EPSV") {
					plan.Hooks = append(plan.Hooks, "ftp.command.passive")
				}
			}
		}
	case "tls.negotiated":
		ftp := fields["tls.application_protocol"].AsString() == "ftp"
		for _, pair := range protectionNames {
			if _, ok := fields[pair.current]; ok && !ftp {
				return ObservationPlan{}, errors.New("FTP protection evidence on tls.negotiated requires tls.application_protocol=ftp")
			}
		}
		if err := checkTLSMode(fields); err != nil {
			return ObservationPlan{}, err
		}
		if ftp && hasLegacyFTPS {
			plan.Hooks = append(plan.Hooks, "ftps.handshake")
			for _, pair := range protectionNames {
				if v, ok := fields[pair.current]; ok {
					plan.add(pair.legacy, v)
				}
			}
		}
	case "ftps.handshake":
		// The legacy input itself explicitly identifies the owning FTP endpoint.
		// It does not establish a TLS version, ALPN, or either protection verdict.
		plan.Hooks = []string{"tls.negotiated"}
		plan.add("tls.application_protocol", routelang.String("ftp"))
		for _, pair := range protectionNames {
			if v, ok := fields[pair.legacy]; ok {
				// Historical mode strings were unconstrained. Keep the original value for
				// legacy handlers. Only publish an observed canonical mode to new handlers.
				if pair.current == "ftp.tls_mode" && !validTLSMode(v.AsString()) {
					continue
				}
				plan.add(pair.current, v)
			}
		}
		if hasLegacyFTPS {
			plan.Hooks = append(plan.Hooks, "ftps.handshake")
		}
	}
	return plan, nil
}

func (p *ObservationPlan) add(name string, value routelang.Value) {
	if p.ExtraFields == nil {
		p.ExtraFields = make(map[string]routelang.Value)
	}
	p.ExtraFields[name] = value
}
func validTLSMode(mode string) bool { return mode == "explicit" || mode == "implicit" }
func checkTLSMode(fields map[string]routelang.Value) error {
	if v, ok := fields["ftp.tls_mode"]; ok && !validTLSMode(v.AsString()) {
		return errors.New("ftp.tls_mode must be explicit or implicit when supplied")
	}
	return nil
}
