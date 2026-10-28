import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct ConfigurationWorkflowReviewTests {
    @Test(arguments: ["", " ", "\n\t", "\u{00a0}"])
    func aBlankNameExplainsWhyTheEditorHoldsItsDraft(_ name: String) {
        #expect(ConfigurationNameField.problem(name) != nil)
    }

    @Test func aUsableNameKeepsItsActualValueAvailableToVoiceOver() {
        #expect(ConfigurationNameField.problem("Work VPN") == nil)
    }

    private enum Failure: Error { case refused }

    @Test func aFailedProxySecretWriteDoesNotPublishAReference() throws {
        var profile = CustomRoutingProfile()
        profile.proxy.mode = .custom
        let before = profile
        #expect(throws: Failure.self) {
            try syncCustomRoutingProxyAuth(username: "review", password: "fixture",
                                           profile: &profile, profileID: "review") { _, _ in
                throw Failure.refused
            }
        }
        #expect(profile == before)
        #expect(profile.proxy.authSource == nil)
    }

    @Test func aStoredProxySecretGetsAReferenceOnlyAfterItIsWritten() throws {
        var profile = CustomRoutingProfile()
        profile.proxy.mode = .custom
        var written = false
        try syncCustomRoutingProxyAuth(username: "review", password: "fixture",
                                       profile: &profile, profileID: "review") { id, secret in
            #expect(id == "review")
            #expect(secret.username == "review")
            #expect(secret.password == "fixture")
            written = true
        }
        #expect(written)
        #expect(profile.proxy.authSource == ProxyAuthSourceRef.ref(forProfile: "review"))
    }

    @Test func theSharedSchemeRunsAndProfilesTheContainingApp() throws {
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .deletingLastPathComponent().deletingLastPathComponent()
        let url = root.appendingPathComponent("SimpleVPN.xcodeproj/xcshareddata/xcschemes/SimpleVPN.xcscheme")
        let xml = try String(contentsOf: url, encoding: .utf8)
        for action in ["LaunchAction", "ProfileAction"] {
            let start = try #require(xml.range(of: "<\(action)"))
            let end = try #require(xml.range(of: "</\(action)>", range: start.lowerBound..<xml.endIndex))
            let body = xml[start.lowerBound..<end.upperBound]
            #expect(body.contains("BuildableName = \"SimpleVPN.app\""))
            #expect(!body.contains("BuildableName = \"com.bragi0.SimpleVPN.PacketTunnel.systemextension\""))
        }
    }
    @Test(arguments: ["https://login.example.test/path", "http://127.0.0.1:8080/auth"])
    func signInAcceptsWebAddresses(_ address: String) throws {
        #expect(SSOAuthModel.accepts(try #require(URL(string: address))))
    }

    @Test(arguments: ["file:///etc/hosts", "javascript:alert(1)", "https://user:secret@example.test/"])
    func signInRejectsNonWebOrEmbeddedCredentialAddresses(_ address: String) throws {
        #expect(!SSOAuthModel.accepts(try #require(URL(string: address))))
    }

    @Test func signInFailureCanBeRetriedAndCancelled() throws {
        let model = SSOAuthModel()
        let url = try #require(URL(string: "https://login.example.test/"))
        model.request(url)
        model.failed()
        #expect(model.problem != nil)
        let generation = model.generation
        model.retry()
        #expect(model.pending == url)
        #expect(model.problem == nil)
        #expect(model.generation > generation)
        model.finish()
        #expect(model.pending == nil)
        #expect(model.problem == nil)
    }

    @Test func invalidSignInReplacesAPreviousPendingRequestWithAnActionableProblem() throws {
        let model = SSOAuthModel()
        model.request(try #require(URL(string: "https://login.example.test/")))
        model.request(try #require(URL(string: "file:///etc/hosts")))
        #expect(model.pending == nil)
        #expect(model.problem != nil)
    }

}
