// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OCAuthSession.swift
//  Drives one libopenconnect sign-in (openconnect_obtain_cookie) and speaks the
//  conversational JSON-lines protocol (OpenConnectAuthWire.swift) on stdin/stdout.
//  The library's callbacks are synchronous, so the conversation is naturally
//  lock-step: a form/cert callback writes its event and blocks reading the app's
//  reply line; SSO hands the browser URL to the app via the external-browser
//  callback (the app owns browser choice — this process opens nothing itself).
//
//  Secrets discipline: the cookie and any password exist only in this process's
//  memory and on the two private pipes; nothing is persisted, nothing goes to
//  stderr, and progress events carry openconnect's PRG_INFO lines only (cookies
//  appear at debug/trace levels, which are never enabled here).
//

import Foundation

// MARK: - C callback trampolines (file-scope: C function pointers can't capture)

private func ocValidateCert(_ priv: UnsafeMutableRawPointer?, _ reason: UnsafePointer<CChar>?) -> CInt {
    guard let priv else { return -1 }
    return Unmanaged<OCAuthSession>.fromOpaque(priv).takeUnretainedValue()
        .validateCert(reason: reason.map { String(cString: $0) } ?? "")
}

private func ocProcessForm(_ priv: UnsafeMutableRawPointer?,
                           _ form: UnsafeMutablePointer<oc_auth_form>?) -> CInt {
    guard let priv, let form else { return CInt(OC_FORM_RESULT_ERR) }
    return Unmanaged<OCAuthSession>.fromOpaque(priv).takeUnretainedValue().processForm(form)
}

private func ocProgress(_ priv: UnsafeMutableRawPointer?, _ level: CInt, _ line: UnsafePointer<CChar>?) {
    guard let priv, let line else { return }
    Unmanaged<OCAuthSession>.fromOpaque(priv).takeUnretainedValue()
        .progress(level: Int(level), line: String(cString: line))
}

private func ocOpenBrowser(_ vpninfo: OpaquePointer?, _ uri: UnsafePointer<CChar>?,
                           _ priv: UnsafeMutableRawPointer?) -> CInt {
    guard let priv, let uri else { return -1 }
    return Unmanaged<OCAuthSession>.fromOpaque(priv).takeUnretainedValue()
        .openBrowser(url: String(cString: uri))
}

// MARK: - Session

final class OCAuthSession {
    private let input: FileHandle
    private let output: FileHandle
    private var inputBuffer = Data()
    private var vpninfo: OpaquePointer?
    private var start: OCAuthStart?
    private var cancelled = false
    private var certRefused = false

    init(input: FileHandle = .standardInput, output: FileHandle = .standardOutput) {
        self.input = input
        self.output = output
    }

    /// Run the whole conversation. Exit status is always 0 — errors travel
    /// INSIDE the JSON (the opnative-helper convention), so the app has one
    /// parsing path.
    func run() -> Never {
        guard let first = readLine_(),
              let message = try? OCAuthJSON.decode(OCAuthClientMessage.self, from: first),
              case .start(let request) = message else {
            exitWithError(kind: OCAuthErrorKind.badRequest,
                          message: "expected a {\"start\":…} line on stdin")
        }
        start = request

        openconnect_init_ssl()
        let priv = Unmanaged.passUnretained(self).toOpaque()
        guard let v = ocauth_vpninfo_new(
            (request.params.useragent?.isEmpty == false ? request.params.useragent! : "SimpleVPN"),
            ocValidateCert, ocProcessForm, ocProgress, priv) else {
            exitWithError(kind: OCAuthErrorKind.badRequest,
                          message: "couldn't initialise the OpenConnect engine")
        }
        vpninfo = v

        openconnect_set_loglevel(v, CInt(PRG_INFO))
        // Certificate trust: OS trust store (+ optional extra CA bundle) verifies
        // by default; validateCert below only runs when that verification FAILS.
        openconnect_set_system_trust(v, 1)
        if let cafile = request.params.cafile, !cafile.isEmpty { openconnect_set_cafile(v, cafile) }
        // SSO: the library raises the sign-in URL here; the APP opens the browser.
        openconnect_set_external_browser_callback(v, ocOpenBrowser)

        if !request.vpnProtocol.isEmpty, openconnect_set_protocol(v, request.vpnProtocol) != 0 {
            exitWithError(kind: OCAuthErrorKind.badRequest,
                          message: "unknown VPN protocol \u{201C}\(request.vpnProtocol)\u{201D}")
        }
        if let os = request.params.reportedOS, !os.isEmpty { openconnect_set_reported_os(v, os) }
        if let ver = request.params.versionString, !ver.isEmpty { openconnect_set_version_string(v, ver) }
        if let name = request.params.localHostname, !name.isEmpty { openconnect_set_localname(v, name) }
        if let proxy = request.params.proxy, !proxy.isEmpty { openconnect_set_http_proxy(v, proxy) }
        if let cert = request.params.certFile, !cert.isEmpty {
            openconnect_set_client_cert(v, cert, request.params.keyFile?.isEmpty == false
                                        ? request.params.keyFile! : nil)
            if let pass = request.params.keyPassword, !pass.isEmpty {
                openconnect_set_key_password(v, pass)
            }
        }

        if openconnect_parse_url(v, request.server) != 0 {
            exitWithError(kind: OCAuthErrorKind.badRequest,
                          message: "that server address couldn't be parsed")
        }
        // --usergroup semantics: an explicit group overrides any path from the URL.
        if let group = request.params.usergroup, !group.isEmpty { openconnect_set_urlpath(v, group) }

        guard openconnect_obtain_cookie(v) == 0 else {
            if cancelled {
                exitWithError(kind: OCAuthErrorKind.cancelled, message: "sign-in cancelled")
            }
            if certRefused {
                exitWithError(kind: OCAuthErrorKind.certRefused,
                              message: "the server's certificate was not accepted")
            }
            exitWithError(kind: OCAuthErrorKind.authFailed,
                          message: "the gateway refused the sign-in")
        }

        // The auth→connect handoff, exactly as openconnect.h documents it:
        // cookie + the exact certificate + the full connect URL + the resolved
        // address (round-robin DNS must not send the tunnel to a sibling server).
        guard let cookieC = openconnect_get_cookie(v) else {
            exitWithError(kind: OCAuthErrorKind.authFailed,
                          message: "sign-in finished without a session cookie")
        }
        let cookie = String(cString: cookieC)
        let servercert = openconnect_get_peer_cert_hash(v).map { String(cString: $0) } ?? ""
        let connectURL = openconnect_get_connect_url(v).map { String(cString: $0) } ?? request.server
        let host = openconnect_get_dnsname(v).map { String(cString: $0) } ?? ""
        // get_hostname returns the IP as it would appear in a URL — IPv6 comes
        // []-wrapped and must be stripped for resolve use (per the header).
        var ip = openconnect_get_hostname(v).map { String(cString: $0) } ?? ""
        ip = ip.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        let resolve = (host.isEmpty || ip.isEmpty || host == ip)
            ? nil : OCAuthDone.Resolve(host: host, ip: ip)
        emit(.done(OCAuthDone(cookie: cookie, servercert: servercert,
                              connectURL: connectURL, resolve: resolve)))
        openconnect_vpninfo_free(v)
        exit(0)
    }

    // MARK: Callbacks

    /// Only reached when system-trust verification FAILED. A configured pin that
    /// matches accepts silently (trust-on-configuration for self-signed
    /// gateways); everything else is the app's decision — and the app never
    /// auto-accepts (cert-verification invariant).
    func validateCert(reason: String) -> CInt {
        guard let v = vpninfo else { return -1 }
        if let pin = start?.params.servercert, !pin.isEmpty {
            let prefixed = pin.contains(":") ? pin : "pin-sha256:\(pin)"
            if openconnect_check_peer_cert_hash(v, prefixed) == 0 { return 0 }
        }
        let fingerprint = openconnect_get_peer_cert_hash(v).map { String(cString: $0) } ?? ""
        var details = ""
        if let d = openconnect_get_peer_cert_details(v) {
            details = String(cString: d)
            openconnect_free_cert_info(v, d)
        }
        emit(.cert(OCAuthCert(fingerprint: fingerprint, details: details, reason: reason)))
        guard let reply = readClientMessage(), case .accept(true) = reply else {
            certRefused = true
            return -1
        }
        return 0
    }

    func processForm(_ form: UnsafeMutablePointer<oc_auth_form>) -> CInt {
        // Apply the configured realm to the auth-group select, mirroring
        // OpenConnectBridge — a groups-only form then needs no round-trip.
        let authgroup = form.pointee.authgroup_opt
        if let authgroup, let realm = start?.params.realm, !realm.isEmpty {
            // `form` is oc_form_opt_select's FIRST member; its address is the select's.
            openconnect_set_option_value(
                UnsafeMutableRawPointer(authgroup).assumingMemoryBound(to: oc_form_opt.self), realm)
        }

        // Collect the fields the app must answer. Hidden fields keep their
        // server-set values, IGNORE-flagged ones are the server's own business,
        // and SSO-token fields are filled by the library from the browser flow.
        var fields: [OCAuthFormField] = []
        var cursor = form.pointee.opts
        while let opt = cursor {
            defer { cursor = opt.pointee.next }
            if opt.pointee.flags & UInt32(OC_FORM_OPT_IGNORE) != 0 { continue }
            if let authgroup, let realm = start?.params.realm, !realm.isEmpty,
               Int(bitPattern: opt) == Int(bitPattern: authgroup) { continue }
            guard let nameC = opt.pointee.name else { continue }
            let id = String(cString: nameC)
            let label = opt.pointee.label.map { String(cString: $0) } ?? id
            switch Int32(opt.pointee.type) {
            case OC_FORM_OPT_TEXT:
                fields.append(.init(id: id, label: label, type: OCAuthFormField.Kind.text, secret: false))
            case OC_FORM_OPT_SSO_USER:
                fields.append(.init(id: id, label: label, type: OCAuthFormField.Kind.ssoUser, secret: false))
            case OC_FORM_OPT_PASSWORD:
                fields.append(.init(id: id, label: label, type: OCAuthFormField.Kind.password, secret: true))
            case OC_FORM_OPT_TOKEN:
                fields.append(.init(id: id, label: label, type: OCAuthFormField.Kind.token, secret: true))
            case OC_FORM_OPT_SELECT:
                let select = UnsafeMutableRawPointer(opt).assumingMemoryBound(to: oc_form_opt_select.self)
                var options: [OCAuthFormField.Option] = []
                let choices = select.pointee.choices
                for i in 0..<Int(max(0, select.pointee.nr_choices)) {
                    guard let choice = choices?[i] else { continue }
                    let value = choice.pointee.name.map { String(cString: $0) } ?? ""
                    options.append(.init(value: value,
                                         label: choice.pointee.label.map { String(cString: $0) } ?? value))
                }
                fields.append(.init(id: id, label: label, type: OCAuthFormField.Kind.select,
                                    secret: false, options: options))
            default:
                continue   // HIDDEN / SSO_TOKEN / future kinds — not the app's to answer
            }
        }
        // Nothing askable (e.g. the post-browser SSO-token form): just proceed.
        guard !fields.isEmpty else { return CInt(OC_FORM_RESULT_OK) }

        emit(.form(OCAuthFormSpec(
            authID: form.pointee.auth_id.map { String(cString: $0) },
            banner: form.pointee.banner.map { String(cString: $0) },
            message: form.pointee.message.map { String(cString: $0) },
            error: form.pointee.error.map { String(cString: $0) },
            fields: fields)))
        guard let reply = readClientMessage(), case .answers(let answers) = reply else {
            cancelled = true
            return CInt(OC_FORM_RESULT_CANCELLED)
        }
        cursor = form.pointee.opts
        while let opt = cursor {
            defer { cursor = opt.pointee.next }
            guard let nameC = opt.pointee.name,
                  let value = answers[String(cString: nameC)] else { continue }
            openconnect_set_option_value(opt, value)
        }
        return CInt(OC_FORM_RESULT_OK)
    }

    func progress(level: Int, line: String) {
        guard level <= Int(PRG_INFO), !line.isEmpty else { return }
        emit(.progress(level: level, message: line))
    }

    func openBrowser(url: String) -> CInt {
        emit(.openURL(url))
        return 0   // the library now waits for the token to come back to it
    }

    // MARK: Wire plumbing

    private func emit(_ event: OCAuthEvent) {
        guard let line = try? OCAuthJSON.encodeLine(event) else { return }
        output.write(line)
    }

    private func exitWithError(kind: String, message: String) -> Never {
        emit(.error(kind: kind, message: message))
        if let v = vpninfo { openconnect_vpninfo_free(v) }
        exit(0)
    }

    private func readClientMessage() -> OCAuthClientMessage? {
        guard let line = readLine_() else { return nil }
        return try? OCAuthJSON.decode(OCAuthClientMessage.self, from: line)
    }

    /// One `\n`-terminated line from stdin, blocking. nil on EOF (the app went
    /// away — every caller treats that as a cancel).
    private func readLine_() -> Data? {
        while true {
            if let nl = inputBuffer.firstIndex(of: 0x0A) {
                let line = inputBuffer.subdata(in: inputBuffer.startIndex..<nl)
                inputBuffer.removeSubrange(inputBuffer.startIndex...nl)
                if line.isEmpty { continue }
                return line
            }
            var chunk = [UInt8](repeating: 0, count: 4096)
            let n = read(input.fileDescriptor, &chunk, chunk.count)
            guard n > 0 else { return nil }
            inputBuffer.append(contentsOf: chunk[0..<n])
        }
    }
}
