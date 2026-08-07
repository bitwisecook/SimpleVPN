import AppKit
import SwiftUI
import Testing
@testable import SimpleVPN

@MainActor
struct ZZProbeTests {
    @Test func probe() {
        for kind in VPNKind.allCases {
            guard let notice = kind.maturityNotice else { continue }
            let v = MaturityBanner(notice: notice,
                                   request: .init(kind: kind, profileID: "t", reason: .untestedKind))
            let s = NSHostingView(rootView: v).fittingSize
            print("PROBE banner \(kind.rawValue): \(s)")
        }
        let t = Text(VPNKind.f5apm.maturityNotice!.detail)
            .font(.callout)
            .fixedSize(horizontal: false, vertical: true)
        print("PROBE paragraph: \(NSHostingView(rootView: t).fittingSize)")
    }
}
