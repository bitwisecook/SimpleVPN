// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  BitwardenTests.swift
//  The Bitwarden sign-in source, driven entirely by fixtures. BITWARDEN IS NOT
//  INSTALLED ON THE MACHINE THIS WAS WRITTEN ON, so nothing here has been seen
//  working against a live vault and nothing here claims to have been: every byte of
//  every fixture comes from a named source, and the report that accompanies this work
//  says plainly which paths are fixture-tested and which are unverified.
//
//  ─── FIXTURE PROVENANCE (bitwarden/clients, `main`, read 2026-08) ──────────────
//
//   • `bw status` output and its three `status` values —
//     `apps/cli/src/commands/status.command.ts` (`Response.success(new TemplateResponse
//     ({serverUrl, lastSync, userEmail, userId, status}))`, and `status()` returning
//     exactly "unauthenticated" | "locked" | "unlocked"), corroborated by the
//     documented example on <https://bitwarden.com/help/cli/>.
//   • The reply envelope `{"success":…,"data":…}` / `{"success":false,"message":…}` —
//     `apps/cli/src/models/response.ts`, and `processResponse` in
//     `apps/cli/src/oss-serve-configurator.ts` (`res.body = commandResponse`, HTTP 400
//     on failure).
//   • The CLI's UNWRAPPED stdout (a template printed as its inner object, a list as
//     its array) and errors going to stderr with exit code 1 — `processResponse` in
//     `apps/cli/src/base-program.ts`.
//   • The item shape — `apps/cli/src/vault/models/cipher.response.ts` (`object: "item"`)
//     over `libs/common/src/models/export/cipher-with-ids.export.ts`, with
//     `apps/cli/src/models/response/login.response.ts` and
//     `libs/common/src/models/export/login.export.ts` for the `login` object's
//     `username` / `password` / `totp` / `uris` fields. The sample VALUES ("jdoe",
//     "myp@ssword123", "JBSWY3DPEHPK3PXP") are Bitwarden's own, from
//     `LoginExport.template()`.
//   • The failure sentences "Not found.", "You are not logged in.", "Vault is locked."
//     and the "More than one result was found…" text — `Response.notFound()`,
//     `Response.multipleResults`, and `errorIfLocked` in
//     `apps/cli/src/oss-serve-configurator.ts`.
//   • The routes `GET /status`, `GET /object/:object/:id`, `GET /list/object/:object` —
//     `apps/cli/src/oss-serve-configurator.ts`; the defaults (`localhost`, 8087) and
//     `--port` / `--hostname` / `--disable-origin-protection` —
//     `apps/cli/src/serve.program.ts` and <https://bitwarden.com/help/cli/>.
//   • `bw unlock --raw` printing the session key — `successResponse()` in
//     `apps/cli/src/key-management/commands/unlock.command.ts` (`res.raw = process.env
//     .BW_SESSION`).
//   • The CLI cannot read a vault without that key: `ServiceContainer` stores the
//     auto-unlock user key through `NodeEnvSecureStorageService` (encrypted with the
//     session key) and `init()` calls `setUserKeyInMemoryIfAutoUserKeySet` so a
//     `BW_SESSION` in the environment can decrypt it. That is what these tests
//     encode as "no session ⇒ locked", and it is why the local service is preferred.
//
//  Nothing here reaches the network, spawns a process, or touches the real defaults
//  domain.
//

import Foundation
import os
import Testing
@testable import SimpleVPN

// MARK: - Fixtures

private nonisolated enum BW {

    // --- `bw serve` replies (enveloped) ------------------------------------

    static func serveStatus(_ state: String,
                            serverUrl: String = "https://vault.bitwarden.com") -> Data {
        Data("""
        {"success":true,"data":{"object":"template","template":{"serverUrl":"\(serverUrl)",\
        "lastSync":"2026-08-01T06:33:51.419Z","userEmail":"jdoe@example.com",\
        "userId":"00000000-0000-0000-0000-000000000000","status":"\(state)"}}}
        """.utf8)
    }

    /// Unauthenticated: Bitwarden nulls the account fields.
    static let serveStatusUnauthenticated = Data("""
    {"success":true,"data":{"object":"template","template":{"serverUrl":null,"lastSync":null,\
    "userEmail":null,"userId":null,"status":"unauthenticated"}}}
    """.utf8)

    /// A self-hosted server (Vaultwarden's default URL shape). NOTHING may key on it.
    static let serveStatusSelfHosted = serveStatus("unlocked", serverUrl: "https://vault.example.internal")

    static let itemID = "3a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9"

    static func serveItem(username: String = "jdoe",
                          password: String = "myp@ssword123",
                          totp: String? = "JBSWY3DPEHPK3PXP") -> Data {
        Data("""
        {"success":true,"data":{"object":"item","id":"\(itemID)","organizationId":null,\
        "folderId":null,"type":1,"reprompt":0,"name":"GR Lab VPN","notes":null,"favorite":false,\
        "login":{"uris":[{"match":null,"uri":"https://tig-vpn.grlab.co.uk"}],\
        "username":"\(username)","password":"\(password)",\
        "totp":\(totp.map { "\"\($0)\"" } ?? "null"),"passwordRevisionDate":null},\
        "collectionIds":[],"revisionDate":"2026-07-30T12:00:00.000Z"}}
        """.utf8)
    }

    static func serveList(_ items: [(id: String, name: String, username: String, password: String)]) -> Data {
        let encoded = items.map {
            """
            {"object":"item","id":"\($0.id)","type":1,"reprompt":0,"name":"\($0.name)",\
            "login":{"username":"\($0.username)","password":"\($0.password)","totp":null}}
            """
        }.joined(separator: ",")
        return Data("{\"success\":true,\"data\":{\"object\":\"list\",\"data\":[\(encoded)]}}".utf8)
    }

    static let serveLocked = Data("{\"success\":false,\"message\":\"Vault is locked.\"}".utf8)
    static let serveNotLoggedIn = Data("{\"success\":false,\"message\":\"You are not logged in.\"}".utf8)
    static let serveNotFound = Data("{\"success\":false,\"message\":\"Not found.\"}".utf8)
    static let serveMultiple = Data("""
    {"success":false,"message":"More than one result was found. Try getting a specific object by \
    `id` instead. The following objects were found:\\n3a1b2c3d-4e5f-6071-8293-a4b5c6d7e8f9\
    \\n9f8e7d6c-5b4a-3021-9876-fedcba987654"}
    """.utf8)

    /// Something that is NOT Bitwarden answering on the port.
    static let stranger = Data("<!doctype html><html><body>hello</body></html>".utf8)

    // --- CLI stdout (already unwrapped by the CLI itself) ------------------

    static let cliStatusLocked = Data("""
    {"serverUrl":"https://vault.bitwarden.com","lastSync":"2026-08-01T06:33:51.419Z",\
    "userEmail":"jdoe@example.com","userId":"00000000-0000-0000-0000-000000000000","status":"locked"}
    """.utf8)

    static let cliStatusUnauthenticated = Data("""
    {"serverUrl":"https://vault.bitwarden.com","lastSync":null,"userEmail":null,"userId":null,\
    "status":"unauthenticated"}
    """.utf8)

    static let cliStatusUnlocked = Data("""
    {"serverUrl":"https://vault.bitwarden.com","lastSync":"2026-08-01T06:33:51.419Z",\
    "userEmail":"jdoe@example.com","userId":"00000000-0000-0000-0000-000000000000","status":"unlocked"}
    """.utf8)

    static let cliItem = Data("""
    {"object":"item","id":"\(itemID)","type":1,"reprompt":0,"name":"GR Lab VPN",\
    "login":{"uris":[{"match":null,"uri":"https://tig-vpn.grlab.co.uk"}],"username":"jdoe",\
    "password":"myp@ssword123","totp":"JBSWY3DPEHPK3PXP","passwordRevisionDate":null}}
    """.utf8)

    static let cliList = Data("""
    [{"object":"item","id":"\(itemID)","type":1,"name":"GR Lab VPN",\
    "login":{"username":"jdoe","password":"myp@ssword123","totp":null}}]
    """.utf8)

    static func ok(_ stdout: Data) -> LocalToolResult {
        LocalToolResult(exitCode: 0, stdout: stdout, stderr: "", timedOut: false)
    }
    static func failed(_ stderr: String) -> LocalToolResult {
        LocalToolResult(exitCode: 1, stdout: Data(), stderr: stderr, timedOut: false)
    }
    static let notRunnable = LocalToolResult(exitCode: -1, stdout: Data(),
                                             stderr: "not an approved tool location", timedOut: false)
}

/// A `bw serve` that answers from a path→reply table. Anything not in the table is
/// "nothing listening", which is what a wrong port really looks like.
private nonisolated func serve(_ table: [String: (Int, Data)]) -> BitwardenServeClient {
    BitwardenServeClient(endpoint: .bitwardenDefault) { url in
        let key = url.path + (url.query.map { "?\($0)" } ?? "")
        guard let hit = table[key] else { return nil }
        return (status: hit.0, body: hit.1)
    }
}

private nonisolated let nothingListening = BitwardenServeClient(endpoint: .bitwardenDefault) { _ in nil }

/// A session key supplier for the CLI path. The shipped one answers nil; these
/// tests drive both halves.
private nonisolated struct FixedSession: BitwardenSessionSupplier {
    var key: String
    func sessionKey() -> BitwardenSessionKey? { BitwardenSessionKey(key) }
}

/// Records every argv and environment a CLI call would have used, so the "never in
/// argv" rule is asserted rather than asserted-in-a-comment.
private nonisolated final class CLISpy: @unchecked Sendable {
    var arguments: [[String]] = []
    var environments: [[String: String]] = []
    var reply: LocalToolResult = BW.ok(BW.cliStatusLocked)

    func client(sessions: any BitwardenSessionSupplier = BitwardenNoSession()) -> BitwardenCLIClient {
        BitwardenCLIClient(sessions: sessions) { arguments, environment in
            self.arguments.append(arguments)
            self.environments.append(environment)
            return self.reply
        }
    }
}

// MARK: - The endpoint: on this Mac, or refused

struct LoopbackEndpointTests {

    @Test func hostAndPortParse() throws {
        let endpoint = try #require(LoopbackEndpoint(parsing: "127.0.0.1:8087"))
        #expect(endpoint.host == "127.0.0.1")
        #expect(endpoint.port == 8087)
        #expect(endpoint.isLoopback)
        #expect(endpoint.loopbackBaseURL?.absoluteString == "http://127.0.0.1:8087")
    }

    @Test func bitwardensDocumentedDefaultIsTheDefault() {
        #expect(LoopbackEndpoint.bitwardenDefault.settingValue == "127.0.0.1:8087")
        #expect(LoopbackEndpoint.bitwardenDefault.isLoopback)
    }

    @Test(arguments: ["localhost:8087", "127.0.0.1:8087", "127.1.2.3:9000", "[::1]:8087"])
    func loopbackFormsAreAccepted(_ raw: String) throws {
        let endpoint = try #require(LoopbackEndpoint(parsing: raw))
        #expect(endpoint.isLoopback, "\(raw) is an address on this Mac")
        #expect(endpoint.loopbackBaseURL != nil)
    }

    /// THE REFUSAL. `bw serve --hostname all` exists and Bitwarden warns that it
    /// lets any machine on the network make requests to a service that asks nothing
    /// of its callers. An address somewhere else is a misconfiguration to refuse.
    @Test(arguments: ["192.168.1.10:8087", "vault.example.com:8087", "10.0.0.1:8087",
                      "0.0.0.0:8087", "[2001:db8::1]:8087"])
    func nonLoopbackIsParsedButRefused(_ raw: String) throws {
        let endpoint = try #require(LoopbackEndpoint(parsing: raw))
        #expect(!endpoint.isLoopback, "\(raw) is not this Mac")
        // Refusal is expressed as "there is no URL", so no caller can forget to check.
        #expect(endpoint.loopbackBaseURL == nil)
    }

    @Test(arguments: ["", "8087", "127.0.0.1", "127.0.0.1:0", "127.0.0.1:70000",
                      "127.0.0.1:eight", "http://127.0.0.1:8087", "127.0.0.1:8087/status",
                      "127.0.0.1:8087:9", ":8087"])
    func malformedIsRejected(_ raw: String) {
        #expect(LoopbackEndpoint(parsing: raw) == nil, "\(raw) is not host:port")
    }

    /// A non-loopback SETTING is not merely flagged — it is not used. SimpleVPN falls
    /// back to Bitwarden's own default rather than sending a vault request off-box.
    @Test func aNonLoopbackSettingIsNotUsed() {
        let store = UserDefaults(suiteName: "bitwarden-endpoint-\(UUID().uuidString)")!
        store.set("192.168.1.10:8087", forKey: BitwardenSettings.endpointKey)
        #expect(BitwardenSettings.configuredEndpoint(store: store) == .bitwardenDefault)
        store.set("127.0.0.1:9000", forKey: BitwardenSettings.endpointKey)
        #expect(BitwardenSettings.configuredEndpoint(store: store)
                == LoopbackEndpoint(host: "127.0.0.1", port: 9000))
        store.removeObject(forKey: BitwardenSettings.endpointKey)
        #expect(BitwardenSettings.configuredEndpoint(store: store) == .bitwardenDefault)
    }

    /// The Settings row says which of the two mistakes it is, because "use
    /// host:port" is useless advice to someone who typed a perfectly good address
    /// for the wrong machine.
    @Test @MainActor func thePaneDistinguishesMalformedFromOffBox() {
        let store = UserDefaults(suiteName: "bitwarden-validate-\(UUID().uuidString)")!
        let settings = SignInSourceSettingsStore(store: store)
        let field = SignInSourceSettings.fields(for: .bitwarden)
            .first { $0.kind == .daemonEndpoint }!
        #expect(settings.validate("127.0.0.1:8087", field: field) == .ok)
        #expect(settings.validate("nonsense", field: field) == .badEndpoint)
        #expect(settings.validate("192.168.1.10:8087", field: field) == .notLoopback)
        #expect(VendorFieldValidation.notLoopback.isProblem)
        #expect(VendorFieldValidation.notLoopback.sentence.contains("127.0.0.1"))
    }
}

// MARK: - Reading Bitwarden's answers

struct BitwardenWireTests {

    @Test(arguments: [("unlocked", BitwardenVaultState.unlocked),
                      ("locked", .locked),
                      ("unauthenticated", .unauthenticated)])
    func serveStatusIsRead(_ raw: String, _ expected: BitwardenVaultState) throws {
        guard case .success(let payload) = BitwardenWire.payload(BW.serveStatus(raw)) else {
            Issue.record("a successful status reply read as a failure")
            return
        }
        #expect(BitwardenWire.state(payload) == expected)
    }

    /// The CLI prints the template's CONTENTS, not the envelope. Both shapes read.
    @Test func cliStatusIsRead() throws {
        guard case .success(let payload) = BitwardenWire.payload(BW.cliStatusLocked) else {
            Issue.record("the CLI's own status shape read as a failure")
            return
        }
        #expect(BitwardenWire.state(payload) == .locked)
    }

    /// SELF-HOSTED AND VAULTWARDEN. Nothing keys on `serverUrl`; a status from a
    /// server that is not bitwarden.com is exactly as good.
    @Test func aSelfHostedServerIsNotTreatedDifferently() throws {
        guard case .success(let payload) = BitwardenWire.payload(BW.serveStatusSelfHosted) else {
            Issue.record("a self-hosted status read as a failure")
            return
        }
        #expect(BitwardenWire.state(payload) == .unlocked)
    }

    @Test func anUnauthenticatedStatusHasNullAccountFields() throws {
        guard case .success(let payload) = BitwardenWire.payload(BW.serveStatusUnauthenticated) else {
            Issue.record("an unauthenticated status read as a failure")
            return
        }
        #expect(BitwardenWire.state(payload) == .unauthenticated)
    }

    @Test func theItemsThreeUsefulFieldsAreLifted() throws {
        guard case .success(let payload) = BitwardenWire.payload(BW.serveItem()) else {
            Issue.record("an item reply read as a failure")
            return
        }
        let item = try #require(BitwardenWire.item(payload))
        #expect(item.username == "jdoe")
        #expect(item.password == "myp@ssword123")
        #expect(item.totpSeed == "JBSWY3DPEHPK3PXP")
        #expect(item.name == "GR Lab VPN")
        #expect(item.id == BW.itemID)
    }

    @Test func aListReplyYieldsEveryItem() throws {
        let data = BW.serveList([
            (BW.itemID, "GR Lab VPN", "jdoe", "myp@ssword123"),
            ("9f8e7d6c-5b4a-3021-9876-fedcba987654", "GR Lab VPN (old)", "jdoe.admin", "other"),
        ])
        guard case .success(let payload) = BitwardenWire.payload(data) else {
            Issue.record("a list reply read as a failure")
            return
        }
        let items = BitwardenWire.items(payload)
        #expect(items.count == 2)
        #expect(items.map(\.username) == ["jdoe", "jdoe.admin"])
    }

    /// The CLI prints a bare array for a list. Same reader.
    @Test func theCLIsBareArrayIsAList() throws {
        guard case .success(let payload) = BitwardenWire.payload(BW.cliList) else {
            Issue.record("the CLI's list shape read as a failure")
            return
        }
        #expect(BitwardenWire.items(payload).count == 1)
    }

    @Test func vendorFailuresBecomeStatesWeCanActOn() {
        #expect(BitwardenWire.error(message: "Vault is locked.") == .locked)
        #expect(BitwardenWire.error(message: "You are not logged in.") == .notSignedIn)
        #expect(BitwardenWire.error(message: "Not found.") == .notFound(""))
        if case .severalMatches = BitwardenWire.error(
            message: "More than one result was found. Try getting a specific object by `id` instead.") {
            // as expected
        } else {
            Issue.record("Bitwarden's multiple-results message wasn't recognised")
        }
    }

    /// A vendor message may contain anything a vendor decided to echo, so what we
    /// are willing to show goes through the same scrubber every tool's stderr does —
    /// first line only, dense tokens removed.
    @Test func anUnknownVendorMessageIsScrubbedBeforeItCouldBeShown() throws {
        let error = BitwardenWire.error(message: "Something odd: hunter2Password9999\nsecond line")
        guard case .unreadable(let detail) = error else {
            Issue.record("an unknown message should stay unreadable, not be classified")
            return
        }
        #expect(!detail.contains("hunter2Password9999"))
        #expect(!detail.contains("second line"))
    }

    /// A CODE is not a SEED. Bitwarden stores base32 secrets and `otpauth://` URLs
    /// in `login.totp`; taking a six-digit number as a seed would freeze one wrong
    /// code for ever, and "222222" happens to be valid base32.
    @Test func onlyASeedIsAcceptedAsASeed() {
        #expect(BitwardenWire.seed("JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP")
        #expect(BitwardenWire.seed("otpauth://totp/GR%20Lab:jdoe?secret=JBSWY3DPEHPK3PXP&issuer=GR")
                != nil)
        #expect(BitwardenWire.seed("123456") == nil)
        #expect(BitwardenWire.seed("222222") == nil)
        #expect(BitwardenWire.seed("22222222") == nil)
    }

    @Test func unreadableBytesAreNotMistakenForAnAnswer() {
        guard case .failure = BitwardenWire.payload(BW.stranger) else {
            Issue.record("HTML read as a Bitwarden reply")
            return
        }
    }

    @Test func itemIDsAreToldApartFromSearchTerms() {
        #expect(BitwardenServeClient.looksLikeItemID(BW.itemID))
        #expect(!BitwardenServeClient.looksLikeItemID("GR Lab VPN"))
        #expect(!BitwardenServeClient.looksLikeItemID("3a1b2c3d-4e5f-6071-8293"))
        #expect(!BitwardenServeClient.looksLikeItemID("zzzzzzzz-4e5f-6071-8293-a4b5c6d7e8f9"))
    }
}

// MARK: - Choosing one item

struct BitwardenItemPickerTests {

    private func item(_ username: String, password: String = "p") -> BitwardenItem {
        BitwardenItem(id: UUID().uuidString, name: "GR Lab VPN",
                      username: username, password: password, totpSeed: nil)
    }

    @Test func oneMatchIsTheAnswer() throws {
        let picked = try BitwardenItemPicker.pick([item("jdoe")], account: "", reference: "GR")
        #expect(picked.username == "jdoe")
    }

    @Test func nothingUsableIsNotFound() {
        #expect(throws: BitwardenProvider.BitwardenError.notFound("GR")) {
            try BitwardenItemPicker.pick([], account: "", reference: "GR")
        }
        // An item with no password can't sign anything in — and that is also what
        // stops a secure note of the same name from being reported as an ambiguity.
        #expect(throws: BitwardenProvider.BitwardenError.notFound("GR")) {
            try BitwardenItemPicker.pick([item("jdoe", password: "")], account: "", reference: "GR")
        }
    }

    @Test func severalMatchesSayHowManyAndHowToFixIt() throws {
        let error = #expect(throws: BitwardenProvider.BitwardenError.self) {
            try BitwardenItemPicker.pick([item("jdoe"), item("jdoe.admin")],
                                         account: "", reference: "GR")
        }
        #expect(error == .severalMatches(2))
        let sentence = try #require(error?.errorDescription)
        #expect(sentence.contains("2 Bitwarden items match"))
        #expect(sentence.contains("ID"))
        #expect(sentence.contains("username"))
    }

    @Test func theUsernamePicksTheRightOne() throws {
        let picked = try BitwardenItemPicker.pick([item("jdoe"), item("jdoe.admin")],
                                                  account: "JDOE.ADMIN", reference: "GR")
        #expect(picked.username == "jdoe.admin")
    }

    @Test func aUsernameThatMatchesNothingSaysSo() {
        #expect(throws: BitwardenProvider.BitwardenError.wrongAccount("someone.else")) {
            try BitwardenItemPicker.pick([item("jdoe")], account: "someone.else", reference: "GR")
        }
    }

    /// Two items with the SAME username is still an ambiguity, and must not be
    /// resolved by picking the first.
    @Test func twoItemsWithTheSameUsernameStayAmbiguous() {
        #expect(throws: BitwardenProvider.BitwardenError.severalMatches(2)) {
            try BitwardenItemPicker.pick([item("jdoe"), item("jdoe")],
                                         account: "jdoe", reference: "GR")
        }
    }
}

// MARK: - The local service

struct BitwardenServeTests {

    @Test func aRunningServiceReportsItsState() async {
        let client = serve(["/status": (200, BW.serveStatus("unlocked"))])
        #expect(await client.state() == .unlocked)
    }

    /// SERVE NOT RUNNING, and WRONG PORT: the same thing from our side of the
    /// socket, and both must read as "this channel can't answer" rather than as a
    /// vault problem.
    @Test func nothingListeningIsNotAnErrorAboutTheVault() async {
        #expect(await nothingListening.state() == nil)
        // A port we can reach that answers something else entirely is also nil —
        // never "unlocked", and never a place to send an item request.
        let stranger = serve(["/status": (200, BW.stranger)])
        #expect(await stranger.state() == nil)
    }

    /// The service answers `/status` even while locked (it is one of the few routes
    /// with no lock guard), which is exactly what makes the four states knowable.
    @Test func aLockedVaultStillAnswersStatus() async {
        let client = serve(["/status": (200, BW.serveStatus("locked"))])
        #expect(await client.state() == .locked)
    }

    @Test func anIDGoesStraightToTheItemRoute() async throws {
        let client = serve(["/status": (200, BW.serveStatus("unlocked")),
                            "/object/item/\(BW.itemID)": (200, BW.serveItem())])
        let item = try await client.item(reference: BW.itemID, account: "")
        #expect(item.username == "jdoe")
        #expect(item.password == "myp@ssword123")
    }

    /// A NAME is a search, not a path: it encodes safely, and it is what lets the
    /// username disambiguate — `get item` simply fails when a term matches several.
    @Test func aNameBecomesASearch() async throws {
        let client = serve([
            "/status": (200, BW.serveStatus("unlocked")),
            "/list/object/items?search=GR%20Lab%20VPN":
                (200, BW.serveList([(BW.itemID, "GR Lab VPN", "jdoe", "myp@ssword123")])),
        ])
        let item = try await client.item(reference: "GR Lab VPN", account: "")
        #expect(item.username == "jdoe")
    }

    @Test func aLockedVaultRefusingAnItemIsReportedAsLocked() async {
        let client = serve(["/status": (200, BW.serveStatus("locked")),
                            "/object/item/\(BW.itemID)": (400, BW.serveLocked)])
        await #expect(throws: BitwardenProvider.BitwardenError.locked) {
            try await client.item(reference: BW.itemID, account: "")
        }
    }

    @Test func notSignedInIsReportedAsNotSignedIn() async {
        let client = serve(["/status": (200, BW.serveStatusUnauthenticated),
                            "/object/item/\(BW.itemID)": (400, BW.serveNotLoggedIn)])
        await #expect(throws: BitwardenProvider.BitwardenError.notSignedIn) {
            try await client.item(reference: BW.itemID, account: "")
        }
    }

    @Test func anItemThatIsNotThereIsNotFound() async {
        let client = serve(["/status": (200, BW.serveStatus("unlocked")),
                            "/object/item/\(BW.itemID)": (400, BW.serveNotFound)])
        await #expect(throws: BitwardenProvider.BitwardenError.notFound("")) {
            try await client.item(reference: BW.itemID, account: "")
        }
    }

    /// Bitwarden's own "more than one result" reply (which it produces for a search
    /// term on the item route) becomes our advice, not its list of IDs.
    @Test func bitwardensOwnAmbiguityBecomesOurAdvice() async throws {
        let client = serve(["/status": (200, BW.serveStatus("unlocked")),
                            "/object/item/\(BW.itemID)": (400, BW.serveMultiple)])
        let error = await #expect(throws: BitwardenProvider.BitwardenError.self) {
            try await client.item(reference: BW.itemID, account: "")
        }
        let sentence = try #require(error?.errorDescription)
        #expect(sentence.contains("Several Bitwarden items match"))
        // The vendor's message lists item IDs; ours does not repeat them.
        #expect(!sentence.contains(BW.itemID))
    }

    /// An endpoint that is not on this Mac never becomes a request.
    @Test func anOffBoxEndpointIsRefusedRatherThanUsed() async throws {
        let endpoint = try #require(LoopbackEndpoint(parsing: "192.168.1.10:8087"))
        let asked = OSAllocatedUnfairLock(initialState: false)
        let client = BitwardenServeClient(endpoint: endpoint) { _ in
            asked.withLock { $0 = true }
            return (status: 200, body: BW.serveItem())
        }
        #expect(await client.state() == nil)
        await #expect(throws: BitwardenProvider.BitwardenError
            .endpointNotLoopback("192.168.1.10:8087")) {
            try await client.item(reference: BW.itemID, account: "")
        }
        #expect(!asked.withLock { $0 }, "a request was sent to an address off this Mac")
    }
}

// MARK: - The CLI

struct BitwardenCLITests {

    /// WITHOUT A SESSION KEY THE CLI CANNOT FETCH, and it says which fix works
    /// rather than pretending the vault is broken. (This is the state a signed-in
    /// user is in whenever SimpleVPN asks: the unlock in their Terminal belongs to
    /// their Terminal.)
    @Test func noSessionMeansNoFetchAndOneClearFix() async throws {
        let spy = CLISpy()
        spy.reply = BW.ok(BW.cliItem)
        let client = spy.client()
        await #expect(throws: BitwardenProvider.BitwardenError.needsSession) {
            try await client.item(reference: BW.itemID, account: "")
        }
        #expect(spy.arguments.isEmpty, "nothing should be run when there is no key to run it with")
        let sentence = try #require(BitwardenProvider.BitwardenError.needsSession.errorDescription)
        #expect(sentence.contains("bw serve"))
    }

    @Test func statusIsReadWithoutASession() async {
        let spy = CLISpy()
        spy.reply = BW.ok(BW.cliStatusLocked)
        #expect(await spy.client().state() == .locked)
        spy.reply = BW.ok(BW.cliStatusUnauthenticated)
        #expect(await spy.client().state() == .unauthenticated)
    }

    /// A tool we will not run answers nothing, and nothing is spawned to find that
    /// out — `LocalToolRunner.locate` has already declined.
    @Test func aToolWeWontRunAnswersNothing() async {
        let client = BitwardenCLIClient(sessions: BitwardenNoSession()) { _, _ in BW.notRunnable }
        #expect(await client.state() == nil)
    }

    /// THE RULE THIS TEST EXISTS FOR: the session key rides the ENVIRONMENT, never
    /// argv. `bw --session <key>` exists and is deliberately unused, because argv is
    /// readable by every process on this Mac.
    @Test func theSessionKeyIsNeverInArgv() async throws {
        let spy = CLISpy()
        spy.reply = BW.ok(BW.cliItem)
        let client = spy.client(sessions: FixedSession(key: "s3cret-session-key=="))
        let item = try await client.item(reference: BW.itemID, account: "")
        #expect(item.password == "myp@ssword123")

        let argv = spy.arguments.flatMap { $0 }
        #expect(!argv.contains { $0.contains("s3cret-session-key") })
        #expect(!argv.contains("--session"))
        #expect(argv.contains(BW.itemID), "the item's own ID is the only thing that rides argv")
        let environment = try #require(spy.environments.first)
        #expect(environment["BW_SESSION"] == "s3cret-session-key==")
        // Built, not inherited: the runner's own environment is the base.
        #expect(environment["HOME"] != nil)
        #expect(environment["DYLD_INSERT_LIBRARIES"] == nil)
    }

    /// A name is a search here too, so both channels ask Bitwarden the same
    /// question and our own picker resolves it.
    @Test func aNameBecomesASearchOnTheCLIToo() async throws {
        let spy = CLISpy()
        spy.reply = BW.ok(BW.cliList)
        let client = spy.client(sessions: FixedSession(key: "k"))
        _ = try await client.item(reference: "GR Lab VPN", account: "")
        let argv = try #require(spy.arguments.first)
        #expect(Array(argv.prefix(4)) == ["list", "items", "--search", "GR Lab VPN"])
        #expect(argv.contains("--nointeraction"),
                "a tool that decides to prompt must fail fast, not wedge a connect")
    }

    @Test func theToolsOwnFailuresAreClassified() async {
        let spy = CLISpy()
        spy.reply = BW.failed("You are not logged in.")
        await #expect(throws: BitwardenProvider.BitwardenError.notSignedIn) {
            try await spy.client(sessions: FixedSession(key: "k"))
                .item(reference: BW.itemID, account: "")
        }
        spy.reply = BW.failed("Vault is locked.")
        await #expect(throws: BitwardenProvider.BitwardenError.locked) {
            try await spy.client(sessions: FixedSession(key: "k"))
                .item(reference: BW.itemID, account: "")
        }
        spy.reply = BW.failed("Not found.")
        await #expect(throws: BitwardenProvider.BitwardenError.notFound("")) {
            try await spy.client(sessions: FixedSession(key: "k"))
                .item(reference: BW.itemID, account: "")
        }
    }

    @Test func aTimeoutIsItsOwnAnswer() async throws {
        let spy = CLISpy()
        spy.reply = LocalToolResult(exitCode: -1, stdout: Data(), stderr: "", timedOut: true)
        let error = await #expect(throws: BitwardenProvider.BitwardenError.self) {
            try await spy.client(sessions: FixedSession(key: "k"))
                .item(reference: BW.itemID, account: "")
        }
        let sentence = try #require(error?.errorDescription)
        #expect(sentence.contains("in time"))
    }
}

// MARK: - The session key's lifecycle

struct BitwardenSessionKeyTests {

    /// READ ONCE. A second read is nil, so a retry surfaces "get a fresh one"
    /// instead of replaying a key the box no longer has.
    @Test func theKeyLeavesOnceAndOnlyAsAnEnvironmentEntry() {
        let key = BitwardenSessionKey("abc123==")
        #expect(key.consumeAsEnvironment() == ["BW_SESSION": "abc123=="])
        #expect(key.consumeAsEnvironment() == nil)
    }

    @Test func discardingEmptiesItUnused() {
        let key = BitwardenSessionKey("abc123==")
        key.discard()
        #expect(key.consumeAsEnvironment() == nil)
    }

    /// It must not outlive the attempt. An expiry the caller never checks still
    /// empties the box, so "held only for one connect attempt" is structural.
    @Test func anExpiredKeyIsGone() {
        let key = BitwardenSessionKey("abc123==", validFor: -1)
        #expect(key.consumeAsEnvironment() == nil)
    }

    /// The shipped supplier answers nil, and that is deliberate: keeping a vault key
    /// is forbidden, and SimpleVPN does not ask for a master password.
    @Test func nothingShippingProducesAKey() {
        #expect(BitwardenNoSession().sessionKey() == nil)
    }
}

// MARK: - Transport preference

private nonisolated struct StubChannel: BitwardenChannel {
    var stubbedState: BitwardenVaultState?
    var stubbedItem: BitwardenItem?
    func state() async -> BitwardenVaultState? { stubbedState }
    func item(reference: String, account: String) async throws -> BitwardenItem {
        guard let stubbedItem else { throw BitwardenProvider.BitwardenError.notFound(reference) }
        return stubbedItem
    }
}

struct BitwardenChannelPreferenceTests {

    /// THE SERVICE FIRST, and the reason is the key rather than the milliseconds:
    /// it is the only channel that reads an item without SimpleVPN handling the
    /// thing that unlocks the vault. So when it answers, the tool is not consulted
    /// at all.
    @Test func theServiceWinsAndTheToolIsNotRunAtAll() async throws {
        let spy = CLISpy()
        let channel = BitwardenLocalChannel(
            serve: serve(["/status": (200, BW.serveStatus("unlocked")),
                          "/object/item/\(BW.itemID)": (200, BW.serveItem())]),
            cli: spy.client(sessions: FixedSession(key: "unused")))
        let item = try await channel.item(reference: BW.itemID, account: "")
        #expect(item.username == "jdoe")
        #expect(spy.arguments.isEmpty, "the tool was run even though the service answered")
    }

    /// No service ⇒ the tool. Which then says what it can say.
    @Test func withoutTheServiceTheToolIsTheFallback() async {
        let spy = CLISpy()
        spy.reply = BW.ok(BW.cliStatusLocked)
        let channel = BitwardenLocalChannel(serve: nothingListening, cli: spy.client())
        #expect(await channel.state() == .locked)
        await #expect(throws: BitwardenProvider.BitwardenError.needsSession) {
            try await channel.item(reference: BW.itemID, account: "")
        }
    }

    /// A FETCH failure from the service is an ANSWER, not a channel problem: falling
    /// back would turn "no such item" into "SimpleVPN can't read your vault".
    @Test func aServiceThatAnswersOwnsTheFailure() async {
        let spy = CLISpy()
        spy.reply = BW.ok(BW.cliItem)
        let channel = BitwardenLocalChannel(
            serve: serve(["/status": (200, BW.serveStatus("unlocked")),
                          "/object/item/\(BW.itemID)": (400, BW.serveNotFound)]),
            cli: spy.client(sessions: FixedSession(key: "k")))
        await #expect(throws: BitwardenProvider.BitwardenError.notFound("")) {
            try await channel.item(reference: BW.itemID, account: "")
        }
        #expect(spy.arguments.isEmpty, "a real answer was retried through the other channel")
    }
}

// MARK: - The provider

struct BitwardenProviderTests {

    @Test func aResolvedItemFillsUsernamePasswordAndACode() async throws {
        let provider = BitwardenProvider(
            reference: BW.itemID, account: "",
            channel: StubChannel(stubbedState: .unlocked,
                                 stubbedItem: BitwardenItem(
                                    id: BW.itemID, name: "GR Lab VPN", username: "jdoe",
                                    password: "myp@ssword123", totpSeed: "JBSWY3DPEHPK3PXP")))
        let raw = try await provider.resolve(profile: "p", fields: [.username, .password, .otp])
        #expect(raw.username == "jdoe")
        #expect(raw.password == "myp@ssword123")
        // Computed locally from the SEED, with the app's own RFC 6238 engine — no
        // second round trip, and no dependence on `bw get totp`, which needs premium.
        let code = try #require(raw.otp)
        #expect(code.count == 6)
        #expect(code.allSatisfy { $0.isNumber })
    }

    /// The code is only computed when the VPN asks for one.
    @Test func noCodeIsComputedWhenNoneIsWanted() async throws {
        let provider = BitwardenProvider(
            reference: BW.itemID,
            channel: StubChannel(stubbedState: .unlocked,
                                 stubbedItem: BitwardenItem(username: "jdoe", password: "p",
                                                            totpSeed: "JBSWY3DPEHPK3PXP")))
        let raw = try await provider.resolve(profile: "p", fields: [.username, .password])
        #expect(raw.otp == nil)
    }

    @Test func anItemWithNoPasswordSaysSo() async {
        let provider = BitwardenProvider(
            reference: "GR Lab VPN",
            channel: StubChannel(stubbedState: .unlocked,
                                 stubbedItem: BitwardenItem(username: "jdoe", password: nil)))
        await #expect(throws: BitwardenProvider.BitwardenError.noPassword("GR Lab VPN")) {
            try await provider.resolve(profile: "p", fields: [.password])
        }
    }

    @Test func noReferenceIsNotAFetch() async {
        let provider = BitwardenProvider(reference: "   ",
                                         channel: StubChannel(stubbedState: .unlocked))
        await #expect(throws: BitwardenProvider.BitwardenError.noItem) {
            try await provider.resolve(profile: "p", fields: [.password])
        }
        let available = await provider.isAvailable(for: "p")
        #expect(!available)
    }

    /// Availability is UNLOCKED, not "installed": every other state cannot serve.
    @Test func onlyAnUnlockedVaultIsAvailable() async {
        for state in BitwardenVaultState.allCases {
            let provider = BitwardenProvider(reference: BW.itemID,
                                             channel: StubChannel(stubbedState: state))
            let available = await provider.isAvailable(for: "p")
            #expect(available == (state == .unlocked), "\(state.rawValue) must not read as usable")
        }
        let unreachable = await BitwardenProvider(reference: BW.itemID,
                                                  channel: StubChannel(stubbedState: nil))
            .isAvailable(for: "p")
        #expect(!unreachable)
    }

    /// No error string may quote a secret. Asserted over every case, because this is
    /// the surface that ends up in a diagnostic bundle.
    @Test func noErrorSentenceCanCarryASecret() {
        let secret = "myp@ssword123"
        let errors: [BitwardenProvider.BitwardenError] = [
            .noItem, .notSignedIn, .locked, .needsSession, .notFound("GR Lab VPN"),
            .severalMatches(3), .noPassword("GR Lab VPN"), .wrongAccount("jdoe"),
            .endpointNotLoopback("192.168.1.10:8087"), .unreadable("something odd"),
        ]
        for error in errors {
            let sentence = error.errorDescription ?? ""
            #expect(!sentence.isEmpty)
            #expect(!sentence.contains(secret))
            #expect(!sentence.contains("BW_SESSION="))
        }
    }
}

// MARK: - The four states

struct BitwardenAvailabilityTests {

    /// READY: the service answering with an unlocked vault.
    @Test func unlockedIsReady() async {
        let adapter = BitwardenVaultAdapter(channel: StubChannel(stubbedState: .unlocked))
        #expect(await adapter.deepScan(quick: .unchecked) == .ready)
    }

    /// NEEDS ONE-TIME SETUP, part one: signed in but locked. Its own state, because
    /// its fix is its own command — and because telling someone who is signed in
    /// that they are not is how they conclude the app cannot see their vault.
    @Test func lockedIsItsOwnStateWithItsOwnFix() async throws {
        let adapter = BitwardenVaultAdapter(channel: StubChannel(stubbedState: .locked))
        #expect(await adapter.deepScan(quick: .unchecked) == .blocked(.vaultLocked))
        let copy = LocalVaultCopyBook.bitwarden
        #expect(copy.headline(for: .vaultLocked).contains("locked"))
        let guidance = try #require(copy.guidance(for: .vaultLocked))
        #expect(guidance.example.contains { $0.text.contains("bw unlock") })
        #expect(guidance.example.contains { $0.text.contains("bw serve") })
        #expect(LocalVaultBlock.vaultLocked.wantsEnablementBanner)
    }

    /// NEEDS ONE-TIME SETUP, part two: nobody signed in.
    @Test func unauthenticatedIsNotSignedIn() async throws {
        let adapter = BitwardenVaultAdapter(channel: StubChannel(stubbedState: .unauthenticated))
        #expect(await adapter.deepScan(quick: .unchecked) == .blocked(.notSignedIn))
        let guidance = try #require(LocalVaultCopyBook.bitwarden.guidance(for: .notSignedIn))
        #expect(guidance.example.contains { $0.text == "bw login" })
    }

    /// NEEDS ONE-TIME SETUP, part three: the service is not running and the tool
    /// cannot answer either. We keep what the cheap pass established rather than
    /// inventing a state — "we couldn't ask" is not "you aren't signed in".
    @Test func nothingAnsweringLeavesTheCheapAnswerAlone() async {
        let adapter = BitwardenVaultAdapter(channel: StubChannel(stubbedState: nil))
        #expect(await adapter.deepScan(quick: .unchecked) == .unchecked)
        #expect(await adapter.deepScan(quick: .blocked(.toolMissing)) == .blocked(.toolMissing))
        #expect(await adapter.deepScan(quick: .notInstalled) == .notInstalled)
    }

    /// INSTALLED OUTSIDE THE ALLOW-LIST. Not "not installed": it demonstrably is,
    /// and we can see where. The fix is one field, and the banner names the path.
    @Test func foundButNotWhereWeWillRunItIsItsOwnState() throws {
        #expect(BitwardenVaultAdapter.availability(toolIsRunnable: false,
                                                   foundOutsideAllowList: true,
                                                   appIsInstalled: false)
                == .blocked(.toolOutsideAllowList))
        let copy = LocalVaultCopyBook.bitwarden
        let headline = copy.headline(for: .toolOutsideAllowList)
        #expect(!headline.lowercased().contains("isn\u{2019}t installed"))
        let guidance = try #require(copy.guidance(for: .toolOutsideAllowList,
                                                  foundAt: "/Users/me/.bun/bin/bw"))
        #expect(guidance.benefit.contains("/Users/me/.bun/bin/bw"))
        #expect(guidance.example.contains { $0.text == "brew install bitwarden-cli" })
    }

    /// NOT INSTALLED — and the app being present is what turns it into an offer with
    /// an install command rather than a row that isn't there.
    @Test func nothingBitwardenAtAllIsNotOffered() {
        #expect(BitwardenVaultAdapter.availability(toolIsRunnable: false,
                                                   foundOutsideAllowList: false,
                                                   appIsInstalled: false) == .notInstalled)
        #expect(BitwardenVaultAdapter.availability(toolIsRunnable: false,
                                                   foundOutsideAllowList: false,
                                                   appIsInstalled: true)
                == .blocked(.toolMissing))
        #expect(BitwardenVaultAdapter.availability(toolIsRunnable: true,
                                                   foundOutsideAllowList: true,
                                                   appIsInstalled: true) == .unchecked)
    }

    /// A cheap scan spawns nothing and asks the network nothing; the state of the
    /// vault is the deep pass's business.
    @Test func everyDeepStateHasOneFixOnScreen() throws {
        for state in BitwardenVaultState.allCases {
            let availability = BitwardenVaultAdapter.availability(for: state)
            guard case .blocked(let block) = availability else { continue }
            let option = try #require(SignInSourceCatalog.vaultOption(.bitwarden,
                                                                      availability: availability))
            #expect(option.guidance != nil,
                    "\(state.rawValue) leaves the user with no way out on screen")
            #expect(!LocalVaultCopyBook.bitwarden.headline(for: block).isEmpty)
        }
    }
}

// MARK: - The row, the settings and the wiring

struct BitwardenIntegrationTests {

    @Test func theVendorIsOnTheSeamWithBothTransports() throws {
        let adapter = try #require(LocalVaultRegistry.adapter(for: LocalVaultVendor.bitwarden))
        #expect(adapter.storedKind == .bitwarden)
        // The daemon first — the preference is declared, not inferred from reading
        // the implementation.
        #expect(adapter.transports == [.localDaemon, .cli])
        #expect(LocalVaultRegistry.adapter(for: CredentialSourceKind.bitwarden)?.vendor == .bitwarden)
    }

    @Test func theRowIsOfferedAndSelectableWhenReady() throws {
        var facts = SignInSourceFacts()
        facts.vaults[.bitwarden] = .ready
        let row = try #require(SignInSourceCatalog.options(facts).first { $0.id == .vault(.bitwarden) })
        #expect(row.role == .fetches)
        #expect(row.isSelectable)
        #expect(row.storedKind == .bitwarden)
        #expect(row.configurableVendor == .bitwarden)
        #expect(row.guidance == nil, "a row that works must not sprout setup instructions")
    }

    /// The desktop app alone is a POINTER at the way in, never a second row. Two
    /// rows for one app, one of them lying, is what the two classes exist to prevent.
    @Test func theAppIsNotAlsoListedAsAPointer() {
        var facts = SignInSourceFacts()
        facts.vaults[.bitwarden] = .blocked(.toolMissing)
        facts.otherApps = [InstalledPasswordApp(bundleID: "com.bitwarden.desktop",
                                                name: "Bitwarden")]
        let options = SignInSourceCatalog.options(facts)
        #expect(options.filter { $0.title == "Bitwarden" }.count == 1)
        #expect(PasswordAppCatalog.gatedVendor(forBundleID: "com.bitwarden.desktop") == .bitwarden)
    }

    /// Switched off means not offered AND not hinted — the pointer list is not a
    /// hiding place for a vendor the user turned off.
    @Test func switchedOffMeansGoneFromBothLists() {
        var facts = SignInSourceFacts()
        facts.vaults[.bitwarden] = .ready
        facts.disabledVendors = [.bitwarden]
        facts.otherApps = [InstalledPasswordApp(bundleID: "com.bitwarden.desktop",
                                                name: "Bitwarden")]
        let options = SignInSourceCatalog.options(facts)
        #expect(!options.contains { $0.title == "Bitwarden" })
        // …and the pane can still see through the switch, which is what lets it say
        // "installed, and you switched it off".
        #expect(facts.rawAvailability(.bitwarden) == .ready)
    }

    @Test func theSourceKindIsWiredEverywhereItIsAsked() {
        #expect(CredentialSourceKind.bitwarden.displayName == "Bitwarden")
        #expect(!CredentialSourceKind.bitwarden.systemImage.isEmpty)
        // A PROMISE, not a capability: the code IS filled in when the item carries a
        // seed, but nobody has watched this work against a live vault, and a broken
        // promise costs a failed sign-in and a consumed code.
        #expect(!CredentialSourceKind.bitwarden.suppliesOTP)
        #expect(SignInFlow.unavailableHeadline(.bitwarden).contains("bw serve"))
    }

    @Test func aStoredSourceRoundTripsWithNoSecretInIt() throws {
        var source = CredentialSource()
        source.kind = .bitwarden
        source.reference = BW.itemID
        source.account = "jdoe"
        let blob = try #require(source.encodedBlob())
        let text = String(decoding: blob, as: UTF8.self)
        // What is stored is a REFERENCE. Prove it: no password, no session key.
        #expect(text.contains(BW.itemID))
        #expect(!text.lowercased().contains("password"))
        #expect(!text.contains("BW_SESSION"))
        #expect(CredentialSource.decode(from: blob) == source)
    }

    @Test func aSourceWithNoItemYieldsNoProvider() throws {
        let adapter = try #require(LocalVaultRegistry.adapter(for: LocalVaultVendor.bitwarden))
        var source = CredentialSource()
        source.kind = .bitwarden
        #expect(adapter.provider(for: source) == nil)
        source.reference = BW.itemID
        #expect(adapter.provider(for: source)?.id == "bitwarden")
    }

    @Test func theSettingsSurfaceCarriesBothFieldsAndTheSwitch() {
        let fields = SignInSourceSettings.fields(for: .bitwarden)
        #expect(fields.count == 2)
        #expect(fields.map(\.settingID)
                == ["creds.bitwarden.tool-path", "creds.bitwarden.daemon-endpoint"])
        // The path field writes the key the runner reads — one notion of "the path
        // the user set", not a settings copy to keep in step.
        #expect(fields[0].defaultsKey == "signin.tool.bw.path")
        #expect(fields[1].defaultsKey == BitwardenSettings.endpointKey)
        #expect(fields[1].kind == .daemonEndpoint)
        #expect(SignInSourceSettings.enabledSettingID(.bitwarden) == "creds.bitwarden.enabled")
        #expect(LocalVaultVendor.bitwarden.settingSlug == "bitwarden")
        #expect(LocalVaultVendor.vendor(withSlug: "bitwarden") == .bitwarden)
    }

    /// The endpoint field's declared default and what the connect path actually uses
    /// are the same value — tied together here so they cannot drift apart.
    @Test func theEndpointFieldsDefaultIsWhatTheConnectPathUses() throws {
        let field = try #require(SignInSourceSettings.fields(for: .bitwarden)
            .first { $0.kind == .daemonEndpoint })
        let empty = UserDefaults(suiteName: "bitwarden-default-\(UUID().uuidString)")!
        #expect(field.emptyMeansDefault == BitwardenSettings.configuredEndpoint(store: empty).settingValue)
        #expect(field.example == LoopbackEndpoint.bitwardenDefault.settingValue)
    }

    /// "Not set" is a WORKING state for the endpoint, and the wording says so —
    /// "SimpleVPN hasn't found one" would be nonsense about an address nobody can
    /// find by looking, and a screen reader gets no other clue.
    @Test @MainActor func anUnsetEndpointReadsAsTheDefaultRatherThanAsAGap() throws {
        let store = UserDefaults(suiteName: "bitwarden-present-\(UUID().uuidString)")!
        let settings = SignInSourceSettingsStore(store: store)
        let field = try #require(SignInSourceSettings.fields(for: .bitwarden)
            .first { $0.kind == .daemonEndpoint })
        let shown = settings.presentation(for: field)
        #expect(shown.value.isEmpty, "the default must never be written into the value")
        #expect(!shown.isSet)
        #expect(shown.prompt == "127.0.0.1:8087")
        #expect(shown.accessibilityValue.contains("127.0.0.1:8087"))
        #expect(!shown.accessibilityValue.contains("hasn\u{2019}t found one"))
        #expect(!shown.validation.isProblem)
        #expect(shown.effectivePath == "127.0.0.1:8087")
    }

    /// An administrator can pin the endpoint by forcing the same key. The row then
    /// shows POLICY's value and is read-only — never the user's stale one while
    /// SimpleVPN uses another, which reads as a bug in this app rather than policy.
    @Test @MainActor func anAdministratorCanPinTheEndpoint() throws {
        let store = ForcingDefaults(suiteName: "bitwarden-mdm-\(UUID().uuidString)")!
        store.forced = [BitwardenSettings.endpointKey: "127.0.0.1:9999"]
        let settings = SignInSourceSettingsStore(store: store)
        let field = try #require(SignInSourceSettings.fields(for: .bitwarden)
            .first { $0.kind == .daemonEndpoint })
        let shown = settings.presentation(for: field)
        #expect(shown.isLockedByPolicy)
        #expect(shown.value == "127.0.0.1:9999")
        #expect(shown.accessibilityValue.contains("Set by your organization"))
        #expect(!shown.canResetToDetected)
    }

    @Test func bitwardensDocumentationLinksAreInTheOneAuditableTable() {
        #expect(VendorDocs.all.contains(VendorDocs.bitwardenCLI))
        #expect(VendorDocs.all.contains(VendorDocs.bitwardenVaultAPI))
        #expect(VendorDocs.bitwardenCLI.url.absoluteString == "https://bitwarden.com/help/cli/")
        #expect(VendorDocs.bitwardenVaultAPI.url.absoluteString
                == "https://bitwarden.com/help/vault-management-api/")
        #expect(LocalVaultCopyBook.bitwarden.primaryDoc == VendorDocs.bitwardenCLI)
    }

    /// NOTHING ASSUMES bitwarden.com. A self-hosted Bitwarden and a Vaultwarden
    /// server are read through the same tool, so no copy may name the hosted service
    /// as though it were the only one.
    @Test func noCopyAssumesTheHostedService() {
        let copy = LocalVaultCopyBook.bitwarden
        var text = [copy.summary, copy.explanation, copy.uncheckedNote ?? ""]
        for (_, guidance) in copy.guidance {
            text.append(guidance.benefit)
            text.append(guidance.settingLocation ?? "")
            text += guidance.example.map { "\($0.caption) \($0.text)" }
        }
        for sentence in text {
            #expect(!sentence.contains("bitwarden.com"),
                    "copy names the hosted service: \(sentence)")
            #expect(!sentence.lowercased().contains("vault.bitwarden"))
        }
        // The explanation does say the honest thing about a self-hosted server.
        #expect(copy.explanation.contains("Your own server"))
    }

    /// The banner is honest about the one thing a user cannot discover for
    /// themselves: while the local service runs, anything on this Mac can read from
    /// it. Bitwarden's design, and ours to disclose.
    @Test func theCopySaysWhatTheLocalServiceCosts() {
        let explanation = LocalVaultCopyBook.bitwarden.explanation
        #expect(explanation.contains("any program on this Mac"))
        #expect(explanation.contains("never sees your master password"))
    }
}

/// A `UserDefaults` that can pretend an administrator forced a key — the same
/// mechanism `ManagedPolicy` reads, without needing a managed device.
private nonisolated final class ForcingDefaults: UserDefaults {
    var forced: [String: String] = [:]

    override func objectIsForced(forKey key: String) -> Bool { forced[key] != nil }
    override func string(forKey defaultName: String) -> String? {
        forced[defaultName] ?? super.string(forKey: defaultName)
    }
    override func object(forKey defaultName: String) -> Any? {
        forced[defaultName] ?? super.object(forKey: defaultName)
    }
}
