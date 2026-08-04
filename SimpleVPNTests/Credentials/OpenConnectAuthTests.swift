// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenConnectAuthTests.swift
//  Pins the ocauth-helper wire protocol (OpenConnectAuthWire.swift is compiled
//  into BOTH the app and the helper, so these round-trips are the contract),
//  the stored-credential form autofill, and the client's conversation handling
//  — driven against a scripted fake helper process (the KeePassXC mock
//  pattern: the real transport, no real gateway), including the cert-refusal
//  invariant (an unverified certificate is never accepted silently).
//

import Foundation
import Testing
import os
@testable import SimpleVPN

// MARK: - Codec round-trips (the wire contract)

struct OpenConnectAuthWireTests {

    private func roundTripClient(_ m: OCAuthClientMessage) throws -> OCAuthClientMessage {
        try OCAuthJSON.decode(OCAuthClientMessage.self, from: OCAuthJSON.encodeLine(m))
    }
    private func roundTripEvent(_ e: OCAuthEvent) throws -> OCAuthEvent {
        try OCAuthJSON.decode(OCAuthEvent.self, from: OCAuthJSON.encodeLine(e))
    }

    @Test func clientMessagesRoundTrip() throws {
        var params = OCAuthParams()
        params.username = "jd"
        params.realm = "Employees"
        params.servercert = "pin-sha256:QQQ"
        params.keyPassword = "hunter2"
        let start = OCAuthStart(server: "vpn.example.com", vpnProtocol: "gp", params: params)
        #expect(try roundTripClient(.start(start)) == .start(start))
        #expect(try roundTripClient(.answers(["username": "jd", "password": "pw"]))
                == .answers(["username": "jd", "password": "pw"]))
        #expect(try roundTripClient(.accept(true)) == .accept(true))
        #expect(try roundTripClient(.accept(false)) == .accept(false))
        #expect(try roundTripClient(.cancel) == .cancel)
    }

    @Test func eventsRoundTrip() throws {
        let form = OCAuthFormSpec(
            authID: "main", banner: "Welcome", message: "Sign in", error: "try again",
            fields: [
                .init(id: "username", label: "Username:", type: OCAuthFormField.Kind.text, secret: false),
                .init(id: "password", label: "Password:", type: OCAuthFormField.Kind.password, secret: true),
                .init(id: "group", label: "GROUP:", type: OCAuthFormField.Kind.select, secret: false,
                      options: [.init(value: "vpn", label: "VPN")]),
            ])
        #expect(try roundTripEvent(.form(form)) == .form(form))
        #expect(try roundTripEvent(.openURL("https://idp/sso")) == .openURL("https://idp/sso"))
        #expect(try roundTripEvent(.progress(level: 1, message: "POST /"))
                == .progress(level: 1, message: "POST /"))
        let cert = OCAuthCert(fingerprint: "pin-sha256:AAA", details: "CN=gw", reason: "self signed")
        #expect(try roundTripEvent(.cert(cert)) == .cert(cert))
        let done = OCAuthDone(cookie: "webvpn=abc", servercert: "pin-sha256:AAA",
                              connectURL: "https://gw:443/tunnel",
                              resolve: .init(host: "gw.example.com", ip: "203.0.113.9"))
        #expect(try roundTripEvent(.done(done)) == .done(done))
        #expect(try roundTripEvent(.error(kind: "authFailed", message: "no"))
                == .error(kind: "authFailed", message: "no"))
    }

    /// The wire keys are a public contract (the helper may ship at a different
    /// version than the app) — pin the exact spellings, not just round-trips.
    @Test func wireKeysAreTheContract() throws {
        let start = OCAuthClientMessage.start(OCAuthStart(server: "s", vpnProtocol: "gp"))
        let startJSON = try #require(try JSONSerialization.jsonObject(
            with: OCAuthJSON.encodeLine(start)) as? [String: Any])
        let startBody = try #require(startJSON["start"] as? [String: Any])
        #expect(startBody["protocol"] as? String == "gp")

        let done = OCAuthEvent.done(OCAuthDone(cookie: "c", servercert: "f", connectURL: "u",
                                               resolve: .init(host: "h", ip: "i")))
        let doneJSON = try #require(try JSONSerialization.jsonObject(
            with: OCAuthJSON.encodeLine(done)) as? [String: Any])
        let doneBody = try #require(doneJSON["done"] as? [String: Any])
        #expect(doneBody["connect-url"] as? String == "u")
        #expect((doneBody["resolve"] as? [String: Any])?["ip"] as? String == "i")

        let open = try #require(try JSONSerialization.jsonObject(
            with: OCAuthJSON.encodeLine(OCAuthEvent.openURL("x"))) as? [String: Any])
        #expect(open["open-url"] as? String == "x")

        let cancel = try #require(try JSONSerialization.jsonObject(
            with: OCAuthJSON.encodeLine(OCAuthClientMessage.cancel)) as? [String: Any])
        #expect(cancel["cancel"] as? Bool == true)
    }

    @Test func unknownKeysRefuseToDecode() {
        #expect(throws: (any Error).self) {
            _ = try OCAuthJSON.decode(OCAuthEvent.self, from: Data(#"{"surprise":1}"#.utf8))
        }
        #expect(throws: (any Error).self) {
            _ = try OCAuthJSON.decode(OCAuthClientMessage.self, from: Data(#"{"cancel":false}"#.utf8))
        }
    }
}

// MARK: - Stored-credential autofill

struct OCAuthFormAutofillTests {

    private func field(_ id: String, _ type: String, secret: Bool = false,
                       options: [OCAuthFormField.Option]? = nil) -> OCAuthFormField {
        .init(id: id, label: id.capitalized, type: type, secret: secret, options: options)
    }

    @Test func storedCredentialsAnswerSilently() {
        let form = OCAuthFormSpec(fields: [
            field("username", OCAuthFormField.Kind.text),
            field("password", OCAuthFormField.Kind.password, secret: true),
        ])
        let r = OCAuthFormAutofill.fill(form, username: "jd", password: "pw")
        #expect(r.answers == ["username": "jd", "password": "pw"])
        #expect(r.unanswered.isEmpty)
    }

    @Test func ssoUserAndTokenFieldsMapToStoredValues() {
        let form = OCAuthFormSpec(fields: [
            field("user", OCAuthFormField.Kind.ssoUser),
            field("otp", OCAuthFormField.Kind.token, secret: true),
        ])
        let r = OCAuthFormAutofill.fill(form, username: "jd", password: "123456")
        #expect(r.answers == ["user": "jd", "otp": "123456"])
    }

    @Test func missingValuesAreReportedNotGuessed() {
        let form = OCAuthFormSpec(fields: [
            field("username", OCAuthFormField.Kind.text),
            field("password", OCAuthFormField.Kind.password, secret: true),
        ])
        let r = OCAuthFormAutofill.fill(form, username: "jd", password: nil)
        #expect(r.answers == ["username": "jd"])
        #expect(r.unanswered.map(\.id) == ["password"])
    }

    @Test func selectsAnswerOnlyWhenThereIsNoChoice() {
        let one = OCAuthFormSpec(fields: [
            field("group", OCAuthFormField.Kind.select, options: [.init(value: "vpn", label: "VPN")]),
        ])
        #expect(OCAuthFormAutofill.fill(one, username: nil, password: nil).answers == ["group": "vpn"])
        let two = OCAuthFormSpec(fields: [
            field("group", OCAuthFormField.Kind.select,
                  options: [.init(value: "a", label: "A"), .init(value: "b", label: "B")]),
        ])
        let r = OCAuthFormAutofill.fill(two, username: nil, password: nil)
        #expect(r.answers.isEmpty)
        #expect(r.unanswered.map(\.id) == ["group"])
    }
}

// MARK: - Conversation against a scripted fake helper

/// A fake `ocauth-helper`: a shell script speaking the real wire format over
/// the real pipes, so the client's spawn/converse/kill path is exercised
/// end-to-end without libopenconnect or a gateway.
private func writeMockHelper(_ body: String) throws -> URL {
    let url = FileManager.default.temporaryDirectory
        .appendingPathComponent("ocauth-mock-\(UUID().uuidString.prefix(8)).sh")
    try Data(("#!/bin/sh\n" + body).utf8).write(to: url)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
    return url
}

struct OpenConnectAuthClientTests {

    @Test func fullConversationFormAnswersOpenURLDone() async throws {
        let helper = try writeMockHelper("""
        read -r start || exit 0
        case "$start" in *'"protocol":"anyconnect"'*) ;; *) printf '%s\\n' '{"error":{"kind":"badRequest","message":"wrong start"}}'; exit 0;; esac
        printf '%s\\n' '{"progress":{"level":1,"message":"Connected to gateway"}}'
        printf '%s\\n' '{"form":{"authID":"main","message":"Please sign in","fields":[{"id":"username","label":"Username:","type":"text","secret":false},{"id":"password","label":"Password:","type":"password","secret":true}]}}'
        read -r answers || exit 0
        case "$answers" in *'"username":"jd"'*) ;; *) printf '%s\\n' '{"error":{"kind":"authFailed","message":"wrong username"}}'; exit 0;; esac
        case "$answers" in *'"password":"s3cret"'*) ;; *) printf '%s\\n' '{"error":{"kind":"authFailed","message":"wrong password"}}'; exit 0;; esac
        printf '%s\\n' '{"open-url":"https://idp.example.com/sso?req=1"}'
        printf '%s\\n' '{"done":{"cookie":"webvpn=abc123","servercert":"pin-sha256:AAAA","connect-url":"https://vpn.example.com:443/tunnel","resolve":{"host":"vpn.example.com","ip":"203.0.113.9"}}}'
        """)
        defer { try? FileManager.default.removeItem(at: helper) }

        let opened = OSAllocatedUnfairLock<[String]>(initialState: [])
        let progress = OSAllocatedUnfairLock<[String]>(initialState: [])
        let handlers = OpenConnectAuthClient.Handlers(
            answerForm: { form in
                let filled = OCAuthFormAutofill.fill(form, username: "jd", password: "s3cret")
                return filled.unanswered.isEmpty
                    ? .answers(filled.answers)
                    : .cancel(unanswered: filled.unanswered.map(\.label))
            },
            openURL: { url in opened.withLock { $0.append(url) } },
            progress: { line in progress.withLock { $0.append(line) } })

        let done = try await OpenConnectAuthClient.authenticate(
            start: OCAuthStart(server: "vpn.example.com", vpnProtocol: "anyconnect"),
            handlers: handlers, helper: helper, killAfter: 30)

        #expect(done.cookie == "webvpn=abc123")
        #expect(done.servercert == "pin-sha256:AAAA")
        #expect(done.connectURL == "https://vpn.example.com:443/tunnel")
        #expect(done.resolve == OCAuthDone.Resolve(host: "vpn.example.com", ip: "203.0.113.9"))
        #expect(opened.withLock { $0 } == ["https://idp.example.com/sso?req=1"])
        #expect(progress.withLock { $0 } == ["Connected to gateway"])
    }

    /// The cert-verification invariant: the default handler REFUSES a
    /// certificate that failed verification, the refusal reaches the helper as
    /// {"accept":false}, and the failure names the fingerprint to pin.
    @Test func certRefusalIsTheDefaultAndNamesTheFingerprint() async throws {
        let helper = try writeMockHelper("""
        read -r start || exit 0
        printf '%s\\n' '{"cert":{"fingerprint":"pin-sha256:BBBB","details":"CN=gw","reason":"self signed certificate"}}'
        read -r reply || exit 0
        case "$reply" in
          *'"accept":false'*) printf '%s\\n' '{"error":{"kind":"certRefused","message":"the server certificate was not accepted"}}';;
          *) printf '%s\\n' '{"done":{"cookie":"MUST-NOT-HAPPEN","servercert":"x","connect-url":"y"}}';;
        esac
        """)
        defer { try? FileManager.default.removeItem(at: helper) }

        let handlers = OpenConnectAuthClient.Handlers(
            answerForm: { _ in .cancel(unanswered: []) },
            openURL: { _ in })   // decideCert keeps its refusing default

        do {
            _ = try await OpenConnectAuthClient.authenticate(
                start: OCAuthStart(server: "gw", vpnProtocol: "gp"),
                handlers: handlers, helper: helper, killAfter: 30)
            Issue.record("an unverified certificate must never authenticate")
        } catch let error as OpenConnectAuthError {
            guard case .certUntrusted(let fingerprint) = error else {
                Issue.record("expected certUntrusted, got \(error)")
                return
            }
            #expect(fingerprint == "pin-sha256:BBBB")
            // The user-facing text carries the pin to configure.
            #expect(error.localizedDescription.contains("pin-sha256:BBBB"))
        }
    }

    /// A form nothing stored can answer cancels the sign-in and says exactly
    /// what the gateway asked for.
    @Test func unansweredFormCancelsWithTheFieldNames() async throws {
        let helper = try writeMockHelper("""
        read -r start || exit 0
        printf '%s\\n' '{"form":{"fields":[{"id":"pin","label":"Smartcard PIN:","type":"password","secret":true}]}}'
        read -r reply || exit 0
        printf '%s\\n' '{"error":{"kind":"cancelled","message":"sign-in cancelled"}}'
        """)
        defer { try? FileManager.default.removeItem(at: helper) }

        let handlers = OpenConnectAuthClient.Handlers(
            answerForm: { form in
                let filled = OCAuthFormAutofill.fill(form, username: "jd", password: nil)
                return filled.unanswered.isEmpty
                    ? .answers(filled.answers)
                    : .cancel(unanswered: filled.unanswered.map(\.label))
            },
            openURL: { _ in })

        do {
            _ = try await OpenConnectAuthClient.authenticate(
                start: OCAuthStart(server: "gw", vpnProtocol: "anyconnect"),
                handlers: handlers, helper: helper, killAfter: 30)
            Issue.record("expected the unanswered form to fail the sign-in")
        } catch let error as OpenConnectAuthError {
            guard case .formUnanswered(let labels) = error else {
                Issue.record("expected formUnanswered, got \(error)")
                return
            }
            #expect(labels == ["Smartcard PIN:"])
        }
    }

    @Test func helperVanishingMidConversationFailsCleanly() async throws {
        let helper = try writeMockHelper("""
        read -r start || exit 0
        exit 0
        """)
        defer { try? FileManager.default.removeItem(at: helper) }
        await #expect(throws: OpenConnectAuthError.self) {
            _ = try await OpenConnectAuthClient.authenticate(
                start: OCAuthStart(server: "gw", vpnProtocol: "gp"),
                handlers: .init(answerForm: { _ in .cancel(unanswered: []) }, openURL: { _ in }),
                helper: helper, killAfter: 30)
        }
    }
}
