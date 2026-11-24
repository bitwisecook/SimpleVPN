// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
@testable import SimpleVPN

struct ConfigSyntaxTests {
    private func tokens(_ kind: ConfigSyntax.Kind, in source: String, format: ConfigSyntax.Format = .automatic) -> [String] {
        ConfigSyntax.spans(in: source, format: format).filter { $0.kind == kind }.map {
            (source as NSString).substring(with: $0.range)
        }
    }

    @Test func importedConfigsUseTheOriginalUTF16Ranges() {
        let wireGuard = "# 🔒\r\n[Interface]\r\nPrivateKey = abc+/=\r\n[Peer]\r\nPersistentKeepalive=25 # comment"
        #expect(tokens(.section, in: wireGuard) == ["[Interface]", "[Peer]"])
        #expect(tokens(.keyword, in: wireGuard) == ["PrivateKey", "PersistentKeepalive"])
        #expect(tokens(.string, in: wireGuard) == ["abc+/="])
        #expect(tokens(.number, in: wireGuard) == ["25"])
        #expect(tokens(.comment, in: wireGuard) == ["# 🔒", "# comment"])
        let pcf = "[main]\nHost=vpn.example.test\n; old server"
        #expect(tokens(.section, in: pcf) == ["[main]"])
        #expect(tokens(.comment, in: pcf) == ["; old server"])

        let ssh = "Host prod\n  IdentityFile \"~/.ssh/my #1 key\" # chosen\n  Port=2222"
        #expect(tokens(.string, in: ssh) == ["prod", "\"~/.ssh/my #1 key\""])
        #expect(tokens(.number, in: ssh) == ["2222"])
        #expect(tokens(.comment, in: ssh) == ["# chosen"])
    }

    @Test func openVPNEmbeddedMaterialAndConnectionBlocks() {
        let source = """
        client
        <key>
        -----BEGIN PRIVATE KEY-----
        aBc=;
        -----END PRIVATE KEY-----
        </key>
        <auth-user-pass>
        #literal-user
        ;literal-password
        </auth-user-pass>
        <connection>
        remote example.test 443 ; endpoint
        </connection>
        """
        #expect(tokens(.keyword, in: source) == ["client", "remote"])
        #expect(tokens(.comment, in: source) == ["; endpoint"])
        #expect(tokens(.literal, in: source) == ["aBc=;", "#literal-user", ";literal-password"])
        #expect(tokens(.section, in: source).contains("-----BEGIN PRIVATE KEY-----"))
        #expect(tokens(.literal, in: "-----BEGIN CERTIFICATE-----\nabc=\n-----END CERTIFICATE-----") == ["abc="])
    }

    @Test func portableJSONAndYAMLKeepQuotedAndEmbeddedComments() {
        let json = ##"{ "value" : "escaped \"#\" 😊", "enabled": true, "priority": -2.5e2 }"##
        #expect(tokens(.keyword, in: json) == ["\"value\"", "\"enabled\"", "\"priority\""])
        #expect(tokens(.comment, in: json).isEmpty)
        #expect(tokens(.literal, in: json) == ["true"])
        #expect(tokens(.number, in: json) == ["-2.5e2"])
        let yaml = """
        vpns:
          - openvpn-configuration: |-
              # retained profile comment
              remote a.test 443
            name: "A #1" # record
        """
        #expect(tokens(.literal, in: yaml) == ["# retained profile comment", "remote a.test 443"])
        #expect(tokens(.keyword, in: yaml) == ["vpns", "openvpn-configuration", "name"])
        #expect(tokens(.string, in: yaml) == ["\"A #1\""])
        #expect(tokens(.comment, in: yaml) == ["# record"])
    }

    @Test func XMLAndShellRespectMultilineBoundaries() {
        let xml = "<AnyConnectProfile note='a > b'>\n<!-- 🖧\n<fake/> -->\n<HostName><![CDATA[a < b]]></HostName></AnyConnectProfile>"
        #expect(tokens(.keyword, in: xml) == ["note"])
        #expect(tokens(.section, in: xml) == ["AnyConnectProfile", "HostName", "HostName", "AnyConnectProfile"])
        #expect(tokens(.comment, in: xml) == ["<!-- 🖧\n<fake/> -->"])
        #expect(tokens(.literal, in: xml) == ["<![CDATA[a < b]]>"])
        let shell = "#!/bin/sh\nprintf 'line one\n# literal' # comment"
        #expect(tokens(.comment, in: shell) == ["#!/bin/sh", "# comment"])
        #expect(tokens(.string, in: shell).contains("# literal'"))
    }

    @Test func routingHandlersHighlightTypedTokensAndCommentsAtOriginalOffsets() {
        let source = #"""
        fn eligible(port: int) -> bool {
            return port >= 1024;
        }
        on check: proxy.pre_connect {
            let label = "🔐 \"#\" //"; // quoted separators stay in the string
            if eligible(port.server) && dns.rd == true { proxy.select_backend(label); }
            ip.dscp = 16/2; # trailing comment
        }
        """#
        let format = ConfigSyntax.Format.routingEvents
        #expect(tokens(.section, in: source, format: format) == ["proxy.pre_connect", "port.server", "dns.rd", "ip.dscp"])
        #expect(tokens(.keyword, in: source, format: format) ==
            ["fn", "eligible", "int", "bool", "return", "on", "let", "if", "eligible", "proxy.select_backend"])
        #expect(tokens(.string, in: source, format: format) == ["port", "port", "check", "label", ##""🔐 \"#\" //""##, "label"])
        #expect(tokens(.comment, in: source, format: format) == ["// quoted separators stay in the string", "# trailing comment"])
        #expect(tokens(.literal, in: source, format: format) == ["true"])
        #expect(tokens(.number, in: source, format: format) == ["1024", "16", "2"])
        let operators = tokens(.punctuation, in: source, format: format)
        #expect(["->", ">=", "&&", "==", "/", "{", "}", ";", ":"].allSatisfy(operators.contains))
        #expect(tokens(.string, in: #"let name = "unfinished // text"#, format: format) == ["name", #""unfinished // text"#])
    }

    @Test func simpleRoutingPreservesIPv6PredicatesAndHyphenatedActions() {
        let source = "on adjust tcp.syn dst 2001:db8::/32 port 443 => clamp-mss 1280 # protected\n" +
            "on bits: ip.packet { if ip.dst in 192.0.2.0/24 { count(); } }"
        #expect(tokens(.string, in: source, format: .routingEvents).contains("2001:db8::/32"))
        #expect(tokens(.keyword, in: source, format: .routingEvents).contains("clamp-mss"))
        #expect(tokens(.keyword, in: source, format: .routingEvents).contains("=>"))
        #expect(tokens(.number, in: source, format: .routingEvents) == ["443", "1280", "192.0.2.0/24"])
        #expect(tokens(.comment, in: source, format: .routingEvents) == ["# protected"])
    }

    @Test func unknownSetupInstructionsRemainPlainText() {
        for source in ["Server: vpn.example.test", "Use this link: https://vpn.test/path",
                       "https://invite.test/join?token=fixture", "<https://invite.test/join?token=fixture>",
                       "Here is your login information."] {
            #expect(ConfigSyntax.spans(in: source, format: .automatic).isEmpty)
        }
        #expect(tokens(.keyword, in: "Server: vpn.example.test", format: .yaml) == ["Server"])
        #expect(tokens(.keyword, in: "host=vpn.example.test", format: .ini) == ["host"])
    }

    @Test func partialInputAndLargePastesHaveBoundedOrderedRanges() {
        for source in ["<", "<!-- open", "<Tag attr=\"incomplete", "[", "\"incomplete",
                       String(repeating: "key: '🛡️'\n", count: 40_000)] {
            for format: ConfigSyntax.Format in [.xml, .openVPN, .yaml, .json, .routingEvents] {
                let result = ConfigSyntax.spans(in: source, format: format)
                #expect(result.count <= ConfigSyntax.maximumSpans)
                var end = 0
                var valid = true
                for span in result {
                    if span.range.length <= 0 || span.range.location < end { valid = false }
                    end = NSMaxRange(span.range)
                }
                #expect(valid)
                #expect(end <= min(source.utf16.count, ConfigSyntax.maximumUnits))
            }
        }
    }
}
