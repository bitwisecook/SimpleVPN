// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"encoding/json"
	"slices"
	"testing"
)

func ftpRun(t *testing.T, source string, events ...map[string]any) (evaluation, error) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"source": source, "events": events})
	if err != nil {
		t.Fatal(err)
	}
	return evaluate(string(raw))
}

func TestParsedPassiveCommandIsOneObservationWithOrderedHooks(t *testing.T) {
	const source = `on refine:ftp.command.passive {proxy.reply_client(200);}
 on general:ftp.command {count();}`
	for _, verb := range []string{"PASV", "ePsV", "pasv", "LIST", "PASS", "PASVX"} {
		r, err := ftpRun(t, source, map[string]any{"event": "ftp.command", "fields": map[string]any{"ftp.command": verb}, "bytes": []int{1, 2, 3}})
		if err != nil || len(r.Steps) != 1 {
			t.Fatal(verb, r, err)
		}
		step := r.Steps[0]
		hooks := []string{"ftp.command"}
		matches := []string{"general"}
		passive := verb == "PASV" || verb == "ePsV" || verb == "pasv"
		if passive {
			hooks = append(hooks, "ftp.command.passive")
			matches = append(matches, "refine")
		}
		if step.Dropped || !slices.Equal(step.Dispatched, hooks) || !slices.Equal(step.Matched, matches) || len(step.Actions) != len(matches) || step.Actions[0].Name != "count" {
			t.Fatal(verb, step)
		}
		if passive && step.Actions[1].Name != "proxy.reply_client" {
			t.Fatal("lost specialization action", step)
		}
		for _, c := range r.Counters {
			want := 1
			if c.ID == "refine" && !passive {
				want = 0
			}
			if c.Events != want || c.Bytes == nil || *c.Bytes != 3*want || c.Drops != 0 {
				t.Fatal(verb, c)
			}
		}
	}
	for _, verb := range []string{"", " PASS", "EPSV ALL", "PASV\r\n", "PAſV", "PASV\u0000"} {
		if _, err := ftpRun(t, source, map[string]any{"event": "ftp.command", "fields": map[string]any{"ftp.command": verb}}); err == nil {
			t.Fatal("accepted invalid parsed verb", verb)
		}
	}
	if _, err := ftpRun(t, source, map[string]any{"event": "ftp.command.passive", "fields": map[string]any{"ftp.command": "EPSV"}}); err == nil {
		t.Fatal("accepted direct synthetic specialization")
	}
	r, err := ftpRun(t, source, map[string]any{"event": "ftp.command"})
	if err != nil || !slices.Equal(r.Steps[0].Dispatched, []string{"ftp.command"}) {
		t.Fatal("absent verb activated a specialization", r, err)
	}
}

func TestComposedFTPDropsStopAndRollbackTransaction(t *testing.T) {
	for _, tc := range []struct {
		general, refine string
		failure         bool
		at              string
	}{
		{"count(); drop();", "count();", false, "general"},
		{"if ftp.data_private {count();}", "count();", true, "general"},
		{"proxy.reply_client(200);", "drop();", false, "refine"},
		{"count();", "if tls.peer_verified {count();}", true, "refine"},
	} {
		r, err := ftpRun(t, "on refine:ftp.command.passive {"+tc.refine+"} on general:ftp.command {"+tc.general+"} on later:ftp.command.passive {count();}", map[string]any{"event": "ftp.command", "fields": map[string]any{"ftp.command": "EPSV"}})
		if err != nil {
			t.Fatal(err)
		}
		f := r.Steps[0]
		want := []string{"general"}
		hooks := []string{"ftp.command"}
		if tc.at == "refine" {
			want = append(want, "refine")
			hooks = append(hooks, "ftp.command.passive")
		}
		if !f.Dropped || (f.Error != "") != tc.failure || len(f.Actions) != 0 || !slices.Equal(f.Matched, want) || !slices.Equal(f.Dispatched, hooks) {
			t.Fatal(tc, f)
		}
		for _, c := range r.Counters {
			if c.Drops != 0 && c.ID != tc.at || c.ID == tc.at && c.Drops != 1 || c.ID == "later" && c.Events != 0 {
				t.Fatal(tc, c)
			}
		}
	}
}

func TestOwnedFTPFieldsShareOnlyObservedControlTLS(t *testing.T) {
	const source = `on secure:ftp.command.passive { if tls.version=="TLS 1.3" && tls.peer_verified && tls.alpn=="ftp" && ftp.control_encrypted && !ftp.data_private && ftp.tls_mode=="explicit" {count();} }`
	complete := map[string]any{"ftp.command": "EPSV", "tls.version": "TLS 1.3", "tls.alpn": "ftp", "tls.peer_verified": true, "ftp.control_encrypted": true, "ftp.data_private": false, "ftp.tls_mode": "explicit"}
	r, err := ftpRun(t, source, map[string]any{"event": "ftp.command", "fields": complete})
	if err != nil || r.Steps[0].Dropped || len(r.Steps[0].Actions) != 1 {
		t.Fatal(r, err)
	}
	delete(complete, "ftp.data_private")
	r, err = ftpRun(t, source, map[string]any{"event": "ftp.command", "fields": complete})
	if err != nil || !r.Steps[0].Dropped || r.Steps[0].Error == "" {
		t.Fatal("inferred data-leg protection", r, err)
	}
	clear := map[string]any{"ftp.command": "EPSV", "ftp.control_encrypted": false}
	r, err = ftpRun(t, source, map[string]any{"event": "ftp.command", "fields": clear})
	if err != nil || !r.Steps[0].Dropped || r.Steps[0].Error == "" {
		t.Fatal("invented TLS evidence", r, err)
	}
	for _, hook := range []string{"ftp.command", "ftp.reply", "ftp.data_offer"} {
		for _, key := range []string{"tls.version", "tls.alpn", "tls.peer_verified"} {
			var sample any = "test"
			if key == "tls.peer_verified" {
				sample = false
			}
			for _, enc := range []any{nil, false} {
				fields := map[string]any{key: sample}
				if enc != nil {
					fields["ftp.control_encrypted"] = enc
				}
				if _, err := ftpRun(t, "", map[string]any{"event": hook, "fields": fields}); err == nil {
					t.Fatal(hook, "admitted cleartext TLS evidence", fields)
				}
			}
		}
	}
}

func TestFTPSCompatibilityIsExplicitlyFTPOwned(t *testing.T) {
	const source = `on old:ftps.handshake { if ftps.mode=="implicit" && ftps.control_encrypted && !ftps.data_private { count(); } }
 on tls:tls.negotiated {count();}`
	canonical := map[string]any{"tls.application_protocol": "ftp", "ftp.tls_mode": "implicit", "ftp.control_encrypted": true, "ftp.data_private": false}
	legacy := map[string]any{"ftps.mode": "implicit", "ftps.control_encrypted": true, "ftps.data_private": false}
	r, err := ftpRun(t, source, map[string]any{"event": "tls.negotiated", "fields": canonical}, map[string]any{"event": "ftps.handshake", "fields": legacy}, map[string]any{"event": "tls.negotiated", "fields": map[string]any{"tls.alpn": "ftp"}}, map[string]any{"event": "tls.negotiated", "fields": map[string]any{"tls.application_protocol": "http"}})
	if err != nil {
		t.Fatal(err)
	}
	for i, f := range r.Steps {
		want := []string{"tls"}
		hooks := []string{"tls.negotiated"}
		if i < 2 {
			want = append(want, "old")
			hooks = append(hooks, "ftps.handshake")
		}
		if f.Dropped || !slices.Equal(f.Matched, want) || !slices.Equal(f.Dispatched, hooks) || len(f.Actions) != len(want) {
			t.Fatal(i, f)
		}
	}
	if _, ok := r.Steps[1].After["tls.version"]; ok {
		t.Fatal("invented version on legacy fixture")
	}
	delete(canonical, "ftp.data_private")
	r, err = ftpRun(t, source, map[string]any{"event": "tls.negotiated", "fields": canonical})
	if err != nil || !r.Steps[0].Dropped || r.Steps[0].Error == "" || len(r.Steps[0].Actions) != 0 {
		t.Fatal(r, err)
	}
	for _, marker := range []string{"", "http"} {
		f := map[string]any{"ftp.control_encrypted": true}
		if marker != "" {
			f["tls.application_protocol"] = marker
		}
		if _, e := ftpRun(t, source, map[string]any{"event": "tls.negotiated", "fields": f}); e == nil {
			t.Fatal("accepted unowned FTP protection evidence")
		}
	}
}

func TestLegacyFixtureCarriesOnlyObservedFieldsIntoGenericTLS(t *testing.T) {
	const source = `on current:tls.negotiated {
	    if tls.application_protocol=="ftp" && ftp.tls_mode=="explicit" &&
	       ftp.control_encrypted && !ftp.data_private {count();}
	}`
	fields := map[string]any{"ftps.mode": "explicit", "ftps.control_encrypted": true, "ftps.data_private": false}
	run := func() frame {
		t.Helper()
		r, err := ftpRun(t, source, map[string]any{"event": "ftps.handshake", "fields": fields})
		if err != nil {
			t.Fatal(err)
		}
		return r.Steps[0]
	}
	f := run()
	if f.Dropped || len(f.Actions) != 1 || !slices.Equal(f.Dispatched, []string{"tls.negotiated"}) {
		t.Fatal(f)
	}
	delete(fields, "ftps.data_private")
	f = run()
	if !f.Dropped || f.Error == "" || len(f.Actions) != 0 {
		t.Fatal(f)
	}
	fields["ftps.data_private"] = false
	fields["ftps.mode"] = "unspecified"
	f = run()
	if !f.Dropped || f.Error == "" {
		t.Fatal(f)
	}
	const historical = `on prior:ftps.handshake {if ftps.mode=="unspecified" {count();}}`
	r, err := ftpRun(t, historical, map[string]any{"event": "ftps.handshake", "fields": fields})
	if err != nil || r.Steps[0].Dropped || len(r.Steps[0].Actions) != 1 {
		t.Fatal(r, err)
	}
}
