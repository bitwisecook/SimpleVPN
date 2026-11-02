// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct DNSWireMessageTests {
    static func query(_ name: String = "Portal.Example", type: UInt8 = 1) -> Data {
        var data = Data([0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0])
        for label in name.split(separator: ".") { data.append(UInt8(label.utf8.count)); data.append(contentsOf: label.utf8) }
        data.append(contentsOf: [0, 0, type, 0, 1]); return data
    }
    @Test func readsQNameAndQuestionWithoutModifyingThePacket() {
        let query = Self.query()
        #expect(DNSWireMessage.questionName(query) == "portal.example")
        #expect(DNSWireMessage.question(query)?.type == 1)
        #expect(DNSWireMessage.question(query)?.dnsClass == 1)
        #expect(query == Self.query())
    }
    @Test func malformedAndCompressedCyclesAreBoundedAndRefused() {
        for length in 0..<17 { #expect(DNSWireMessage.questionName(Data(repeating: 0, count: length)) == nil) }
        var cycle = Self.query(); cycle[12] = 0xc0; cycle[13] = 12
        #expect(DNSWireMessage.questionName(cycle) == nil)
        var oversizedLabel = Self.query(); oversizedLabel[12] = 64
        #expect(DNSWireMessage.questionName(oversizedLabel) == nil)
        var twoQuestions = Self.query(); twoQuestions[5] = 2
        #expect(DNSWireMessage.questionName(twoQuestions) == nil)
        #expect(DNSWireMessage.questionName(Data(repeating: 0, count: 65_536)) == nil)
    }
    @Test func responseMustMatchIDNameTypeClassAndOpcode() {
        let query = Self.query()
        var response = query; response[2] = 0x81; response[3] = 0x80
        #expect(DNSWireMessage.response(response, matches: query))
        var wrong = response; wrong[0] = 0
        #expect(!DNSWireMessage.response(wrong, matches: query))
        var other = Self.query("other.example"); other[2] = 0x81
        #expect(!DNSWireMessage.response(other, matches: query))
        var aaaa = Self.query(type: 28); aaaa[2] = 0x81
        #expect(!DNSWireMessage.response(aaaa, matches: query))
        var wrongClass = response; wrongClass[wrongClass.count - 1] = 3
        #expect(!DNSWireMessage.response(wrongClass, matches: query))
    }
    @Test func unavailableResolverReturnsServfailWithOriginalTransactionID() throws {
        let query = Self.query()
        let error = try #require(DNSWireMessage.failure(for: query))
        #expect(error.prefix(2) == query.prefix(2))
        #expect(error[3] & 0x0f == 2)
        #expect(DNSWireMessage.question(error, response: true)?.name == "portal.example")
        #expect(error[5] == 1)
        #expect(DNSWireMessage.response(error, matches: query))
    }
}
