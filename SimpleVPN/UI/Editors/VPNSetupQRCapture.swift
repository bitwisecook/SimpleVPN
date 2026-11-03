// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import AVFoundation
import SwiftUI
import Vision

@MainActor
final class VPNSetupQRCapture: NSObject, NSWindowDelegate, AVCaptureMetadataOutputObjectsDelegate {
    private var panel: NSPanel?
    private var screenshot: Process?
    private var camera: CameraSession?
    private var cameraResult: (@MainActor @Sendable (String?) -> Void)?
    private var revision = 0

    static var hasClipboardInput: Bool {
        NSPasteboard.general.canReadObject(forClasses: [NSString.self, NSImage.self, NSURL.self],
                                          options: [.urlReadingFileURLsOnly: true])
    }

    func decode(_ data: Data, completion: @escaping @MainActor @Sendable (String?) -> Void) {
        let current = revision
        Task {
            let result = await Task.detached(priority: .userInitiated) {
                Self.qrPayload(in: data)
            }.value
            guard revision == current else { return }
            completion(result)
        }
    }

    nonisolated private static func qrPayload(in data: Data) -> String? {
        let request = VNDetectBarcodesRequest()
        request.symbologies = [.qr]
        do { try VNImageRequestHandler(data: data).perform([request]) }
        catch { return nil }
        let payloads = Set((request.results ?? []).compactMap(\.payloadStringValue))
        return payloads.count == 1 ? payloads.first : nil
    }

    func showScreenButton(completion: @escaping @MainActor @Sendable (String?) -> Void) {
        close()
        let button = NSHostingView(rootView: Button("Capture QR", systemImage: "qrcode.viewfinder") {
            [weak self] in self?.captureScreen(completion: completion)
        }.padding(12))
        let panel = makePanel(title: "VPN QR Code", size: NSSize(width: 170, height: 48))
        panel.contentView = button
        panel.hidesOnDeactivate = false
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.makeKeyAndOrderFront(nil)
    }

    private func captureScreen(completion: @escaping @MainActor @Sendable (String?) -> Void) {
        panel?.orderOut(nil)
        let current = revision
        let file = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".png")
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/sbin/screencapture")
        process.arguments = ["-i", "-s", "-x", file.path]
        process.terminationHandler = { [weak self] process in
            let data = process.terminationStatus == 0 ? try? Data(contentsOf: file) : nil
            try? FileManager.default.removeItem(at: file)
            Task { @MainActor [weak self] in
                guard let self, revision == current else { return }
                screenshot = nil
                close()
                NSApp.activate()
                if let data { decode(data, completion: completion) }
            }
        }
        do {
            try process.run()
            screenshot = process
        } catch {
            close()
            completion(nil)
        }
    }

    func showCamera(completion: @escaping @MainActor @Sendable (String?) -> Void) {
        close()
        let current = revision
        Task {
            let allowed = await AVCaptureDevice.requestAccess(for: .video)
            guard revision == current else { return }
            guard allowed, let device = AVCaptureDevice.default(for: .video),
                  let input = try? AVCaptureDeviceInput(device: device) else {
                showCameraError("Allow camera access in System Settings, or paste a QR image.")
                return
            }
            let camera = CameraSession()
            let output = AVCaptureMetadataOutput()
            guard camera.session.canAddInput(input), camera.session.canAddOutput(output) else {
                showCameraError("This camera couldn’t be opened. You can paste a QR image instead.")
                return
            }
            camera.session.addInput(input)
            camera.session.addOutput(output)
            guard output.availableMetadataObjectTypes.contains(.qr) else {
                showCameraError("This camera couldn’t scan QR codes. You can paste a QR image instead.")
                return
            }
            output.setMetadataObjectsDelegate(self, queue: .main)
            output.metadataObjectTypes = [.qr]
            let preview = AVCaptureVideoPreviewLayer(session: camera.session)
            preview.videoGravity = .resizeAspectFill
            let view = NSView()
            view.layer = preview
            view.wantsLayer = true
            view.setAccessibilityLabel("Camera preview. Point the camera at a VPN QR code.")
            cameraResult = completion
            self.camera = camera
            let panel = makePanel(title: "Point the Camera at a VPN QR Code",
                                  size: NSSize(width: 480, height: 320))
            panel.contentView = view
            panel.makeKeyAndOrderFront(nil)
            camera.start()
        }
    }

    nonisolated func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject],
                                    from connection: AVCaptureConnection) {
        let codes = Set(metadataObjects.compactMap { ($0 as? AVMetadataMachineReadableCodeObject)?.stringValue })
        guard codes.count == 1, let payload = codes.first else { return }
        let outputID = ObjectIdentifier(output)
        MainActor.assumeIsolated {
            guard camera?.session.outputs.contains(where: { ObjectIdentifier($0) == outputID }) == true,
                  let completion = cameraResult else { return }
            close()
            completion(payload)
        }
    }

    private func showCameraError(_ message: String) {
        let alert = NSAlert()
        alert.messageText = "Camera Unavailable"
        alert.informativeText = message
        if let window = NSApp.keyWindow { alert.beginSheetModal(for: window) }
    }

    private func makePanel(title: String, size: NSSize) -> NSPanel {
        let panel = NSPanel(contentRect: NSRect(origin: .zero, size: size),
                            styleMask: [.titled, .closable, .utilityWindow], backing: .buffered, defer: false)
        panel.title = title
        panel.level = .floating
        panel.isReleasedWhenClosed = false
        panel.delegate = self
        panel.center()
        self.panel = panel
        return panel
    }

    func windowWillClose(_ notification: Notification) { close() }

    func close() {
        revision += 1
        screenshot?.terminate()
        screenshot = nil
        camera?.stop()
        camera = nil
        cameraResult = nil
        panel?.delegate = nil
        panel?.close()
        panel = nil
    }
}

// Configuration completes before start. Blocking start and stop operations run
// in order on this session's queue, outside the main actor.
private nonisolated final class CameraSession: @unchecked Sendable {
    let session = AVCaptureSession()
    private let queue = DispatchQueue(label: "com.bragi0.SimpleVPN.qr-camera")

    func start() { queue.async { self.session.startRunning() } }
    func stop() { queue.async { self.session.stopRunning() } }
}
