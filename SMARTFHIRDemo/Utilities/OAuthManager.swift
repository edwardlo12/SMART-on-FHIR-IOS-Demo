import Foundation
import SMART
import Combine
import WebKit

class OAuthManager: ObservableObject {
    @Published var isAuthorized = false
    @Published var accessToken: String?
    @Published var idToken: String?
    @Published var patientId: String?

    var client: SMART.Client
    private var pendingAuthorizeCompletion: ((Bool, Error?) -> Void)?

    init() {
        client = SMART.Client(
            baseURL: URL(string: FHIRConfig.baseURL)!,
            settings: [
                "client_id": FHIRConfig.clientId,
                "redirect": FHIRConfig.redirectURI,
                "scope": FHIRConfig.scopes
            ]
        )
    }

    func authorize(completion: @escaping (Bool, Error?) -> Void) {
        self.pendingAuthorizeCompletion = completion
        let cb: (SMART.Patient?, Error?) -> Void = { [weak self] patient, error in
            self?.handleAuthorizeCallback(patient: patient, error: error)
        }
        client.authorize(callback: cb)
    }

    private func handleAuthorizeCallback(patient: SMART.Patient?, error: Error?) {
        guard let completion = pendingAuthorizeCompletion else { return }
        pendingAuthorizeCompletion = nil

        if let error = error {
            DispatchQueue.main.async {
                self.isAuthorized = false
                completion(false, error)
            }
            return
        }

        if let patient = patient {
            DispatchQueue.main.async {
                self.isAuthorized = true
                self.patientId = patient.id?.string
                print("[DEBUG] Set patientId from authorize: \(self.patientId ?? "nil")")
                completion(true, nil)
            }
            return
        }

        // Fallback: try to extract patient id from tokens/server
        print("[DEBUG] client.server raw: \(String(describing: self.client.server))")
        self.collectTokensFromServerIfNeeded()
        print("[DEBUG] collected accessToken: \(self.accessToken ?? "(nil)") idToken: \(self.idToken ?? "(nil)")")
        if let extracted = tryExtractPatientIdFromTokenOrServer() {
            DispatchQueue.main.async {
                self.isAuthorized = true
                self.patientId = extracted
                print("[DEBUG] Extracted patientId from token/server: \(extracted)")
                completion(true, nil)
            }
            return
      }

        print("[DEBUG] No patient provided by authorize callback; patientId not set. Treating as incomplete auth.")
        DispatchQueue.main.async {
            self.isAuthorized = false
            self.patientId = nil
            completion(false, nil)
        }
    }

    func handleRedirect(url: URL) {
        // Only handle redirect if SDK is awaiting an auth callback.
        guard client.awaitingAuthCallback else {
            print("[DEBUG] handleRedirect: client is not awaiting auth callback; ignoring redirect")
            // Clear selecting flag to avoid stuck state if user cancelled flow
            DispatchQueue.main.async {
            }
            return
        }

        // Let the SDK process the redirect URL
        let handled = client.didRedirect(to: url)
        print("[DEBUG] handleRedirect: client.didRedirect returned \(handled)")

        // Try to extract patient id or tokens from the SDK server state
        if let extracted = tryExtractPatientIdFromTokenOrServer() {
            DispatchQueue.main.async {
                self.isAuthorized = true
                self.patientId = extracted
                print("[DEBUG] Extracted patientId after redirect: \(extracted)")
            }
        }
    }

    // MARK: - Discovery / Revocation / RP logout helpers

    private func fetchDiscovery(completion: @escaping ([String: Any]?) -> Void) {
        guard let discovery = FHIRConfig.discoveryURL, let url = URL(string: discovery) else { completion(nil); return }
        URLSession.shared.dataTask(with: url) { data, resp, err in
            guard let data = data, err == nil,
                  let json = try? JSONSerialization.jsonObject(with: data, options: []),
                  let dict = json as? [String: Any] else {
                completion(nil)
                return
            }
            // If SMART discovery contains an issuer, try fetch OIDC discovery and merge
            if let issuer = dict["issuer"] as? String, let issuerURL = URL(string: issuer) {
                let oidcURL = issuerURL.appendingPathComponent(".well-known/openid-configuration")
                URLSession.shared.dataTask(with: oidcURL) { oidcData, _, _ in
                    if let oidcData = oidcData,
                       let oidcJson = try? JSONSerialization.jsonObject(with: oidcData, options: []),
                       let oidcDict = oidcJson as? [String: Any] {
                        var merged = dict
                        merged["_oidc"] = oidcDict
                        completion(merged)
                        return
                    }
                    completion(dict)
                }.resume()
                return
            }
            completion(dict)
        }.resume()
    }

    private func discoveryRevocationAndEndSession(from dict: [String: Any]?) -> (revocation: String?, endSession: String?) {
        guard let dict = dict else { return (nil, nil) }
        if let rev = dict["revocation_endpoint"] as? String { return (rev, dict["end_session_endpoint"] as? String) }
        if let oidc = dict["_oidc"] as? [String: Any] {
            return (oidc["revocation_endpoint"] as? String, oidc["end_session_endpoint"] as? String)
        }
        return (nil, nil)
    }

    private func isLikelyJWT(_ s: String) -> Bool {
        let parts = s.split(separator: ".")
        if parts.count < 2 { return false }
        let allowed = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=")
        for p in parts {
            let str = String(p)
            if str.rangeOfCharacter(from: allowed.inverted) != nil { return false }
        }
        return true
    }

    private func revokeToken(_ token: String, endpoint: String, completion: @escaping (Bool) -> Void) {
        guard let url = URL(string: endpoint) else { completion(false); return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        let body = "token=\(token)&token_type_hint=access_token&client_id=\(FHIRConfig.clientId)"
        req.httpBody = body.data(using: .utf8)
        req.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        URLSession.shared.dataTask(with: req) { data, resp, err in
            if let http = resp as? HTTPURLResponse, (200...299).contains(http.statusCode) {
                completion(true)
            } else {
                completion(false)
            }
        }.resume()
    }

    private func doRPInitiatedLogout(idToken: String?) {
        let callLogoutURL: (String) -> Void = { urlStr in
            guard let url = URL(string: urlStr) else { return }
            DispatchQueue.main.async { UIApplication.shared.open(url) }
        }

        if let endSession = FHIRConfig.endSessionEndpoint, let post = FHIRConfig.postLogoutRedirect {
            let urlStr = "\(endSession)?id_token_hint=\(idToken ?? "")&post_logout_redirect_uri=\(post)"
            callLogoutURL(urlStr)
            return
        }
    }

    // Debug: dump client.server

    // MARK: - Token / patient extraction helpers

    private func tryExtractPatientIdFromTokenOrServer() -> String? {
        collectTokensFromServerIfNeeded()
        if let token = accessToken, let id = parseJWTForPatientId(token) { return id }
        if let idtok = idToken, let id = parseJWTForPatientId(idtok) { return id }
        let mirror = Mirror(reflecting: client.server)
        if let id = searchMirrorForPatientId(mirror) { return id }
        return nil
    }

    private func searchMirrorForPatientId(_ mirror: Mirror, depth: Int = 0) -> String? {
        if depth > 6 { return nil }
        for child in mirror.children {
            if let s = child.value as? String {
                if let jwt = findJWTInString(s), let id = parseJWTForPatientId(jwt) { return id }
                if let id = extractPatientIdFromJSONString(s) { return id }
            } else {
                let desc = String(describing: child.value)
                if let jwt = findJWTInString(desc), let id = parseJWTForPatientId(jwt) { return id }
                if let id = extractPatientIdFromJSONString(desc) { return id }
            }
            let childMirror = Mirror(reflecting: child.value)
            if let id = searchMirrorForPatientId(childMirror, depth: depth + 1) { return id }
        }
        return nil
    }

    private func findJWTInString(_ s: String) -> String? {
        let tokens = s.split(separator: " ")
        for t in tokens {
            let str = String(t)
            let parts = str.split(separator: ".")
            if parts.count >= 2 && parts.count <= 3 { return str }
        }
        return nil
    }

    private func parseJWTForPatientId(_ jwt: String) -> String? {
        let comps = jwt.split(separator: ".")
        guard comps.count >= 2 else { return nil }
        let payloadB64 = String(comps[1])
        var base64 = payloadB64.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let padLen = 4 - (base64.count % 4)
        if padLen < 4 { base64 += String(repeating: "=", count: padLen) }
        guard let data = Data(base64Encoded: base64) else { return nil }
        guard let json = try? JSONSerialization.jsonObject(with: data, options: []), let dict = json as? [String: Any] else { return nil }
        if let p = dict["patient"] as? String { return p }
        if let p = dict["patient_id"] as? String { return p }
        if let p = dict["patientId"] as? String { return p }
        if let sub = dict["sub"] as? String {
            if sub.contains("Patient/") { return String(sub.split(separator: "/").last ?? "") }
        }
        if let fhirUser = dict["fhirUser"] as? String, fhirUser.contains("Patient/") { return String(fhirUser.split(separator: "/").last ?? "") }
        if let patientObj = dict["patient"] as? [String: Any], let id = patientObj["id"] as? String { return id }
        return nil
    }

    private func extractPatientIdFromJSONString(_ s: String) -> String? {
        guard let data = s.data(using: .utf8) else { return nil }
        if let json = try? JSONSerialization.jsonObject(with: data, options: []), let dict = json as? [String: Any] {
            if let p = dict["patient"] as? String { return p }
            if let p = dict["patient_id"] as? String { return p }
            if let p = dict["patientId"] as? String { return p }
            if let patientObj = dict["patient"] as? [String: Any], let id = patientObj["id"] as? String { return id }
        }
        return nil
    }

    // MARK: - Keychain helpers

    func saveTokenToKeychain() {
        if let token = self.accessToken { KeychainHelper.shared.saveToken(token, forKey: "accessToken") }
    }
    func loadTokenFromKeychain() {
        if let token = KeychainHelper.shared.getToken(forKey: "accessToken") { self.accessToken = token; self.isAuthorized = true }
    }

    // MARK: - Logout / reauthorize flows

    func logout() {
        // Try to ask the SDK client to reset/abort if it exposes such API (best-effort)
        attemptClientReset()

        collectTokensFromServerIfNeeded()
        let group = DispatchGroup()
        var didRevoke = false
        let tokenToRevoke = self.accessToken
        let idTokenHint = self.idToken

        if let token = tokenToRevoke {
            if let revokeEndpoint = FHIRConfig.revocationEndpoint {
                group.enter()
                revokeToken(token, endpoint: revokeEndpoint) { ok in didRevoke = didRevoke || ok; group.leave() }
            } else if FHIRConfig.discoveryURL != nil {
                group.enter()
                fetchDiscovery { dict in
                    let endpoints = self.discoveryRevocationAndEndSession(from: dict)
                    if let rev = endpoints.revocation {
                        self.revokeToken(token, endpoint: rev) { ok in didRevoke = didRevoke || ok; group.leave() }
                    } else { group.leave() }
                }
            }
        }

        group.notify(queue: .main) {
            self.isAuthorized = false
            self.accessToken = nil
            self.patientId = nil
            KeychainHelper.shared.deleteToken(forKey: "accessToken")
            self.client = SMART.Client(baseURL: URL(string: FHIRConfig.baseURL)!, settings: ["client_id": FHIRConfig.clientId, "redirect": FHIRConfig.redirectURI, "scope": FHIRConfig.scopes])
            if let cookies = HTTPCookieStorage.shared.cookies { for cookie in cookies { HTTPCookieStorage.shared.deleteCookie(cookie) } }
            let dataTypes = WKWebsiteDataStore.allWebsiteDataTypes()
            WKWebsiteDataStore.default().removeData(ofTypes: dataTypes, modifiedSince: Date(timeIntervalSince1970: 0)) { print("[DEBUG] Cleared WKWebsiteDataStore") }
            // Prefer RP logout if available
            self.doRPInitiatedLogout(idToken: idTokenHint)
        }
    }

    private func attemptClientReset() {
        // The SMART SDK's Client exposes Swift methods `reset()` and may also support `abort()`.
        // Call them on the main thread; if the client bridges to NSObject we can call selectors,
        // otherwise call the Swift API directly.
        DispatchQueue.main.async {
            // Fallback: call Swift API if available
            // reset() exists on SMART.Client; call it to clear internal state
            self.client.reset()
        }
    }

    // MARK: - Token extraction helpers

    private func extractTokenFromJSONString(_ s: String) -> String? {
        guard let data = s.data(using: .utf8) else { return nil }
        if let json = try? JSONSerialization.jsonObject(with: data, options: []), let dict = json as? [String: Any] {
            if let at = dict["access_token"] as? String { return at }
            if let it = dict["id_token"] as? String { return it }
            if let rt = dict["refresh_token"] as? String { return rt }
            if let tokenResp = dict["tokenResponse"] as? [String: Any] {
                if let at = tokenResp["access_token"] as? String { return at }
                if let it = tokenResp["id_token"] as? String { return it }
            }
        }
        return nil
    }


    // Start a patient re-selection flow without forcing a full re-login (uses prompt=select_account or embedded SDK flow)
    func startPatientSelection() {
        // Non-forced selection: prefer SDK's embedded authorize which may present
        // a native patient selector without opening the browser.
        print("[DEBUG] startPatientSelection: invoking SDK client.authorize() as primary path")
        client.authorize(callback: { [weak self] patient, error in
            self?.handleAuthorizeCallback(patient: patient, error: error)
        })
    }

    // Try to read auth.settings from client.server via Mirror (returns settings dictionary if found)
    private func tryGetAuthSettings() -> [String: Any]? {
        let mirror = Mirror(reflecting: client.server)
        for child in mirror.children {
            if child.label == "auth" {
                let authMirror = Mirror(reflecting: child.value)
                for aChild in authMirror.children {
                    if aChild.label == "some" {
                        let someMirror = Mirror(reflecting: aChild.value)
                        for sm in someMirror.children {
                            if sm.label == "settings", let dict = sm.value as? [String: Any] {
                                return dict
                            }
                        }
                    }
                }
            }
            // also check top-level authSettings
            if child.label == "authSettings", let dict = child.value as? [String: Any] {
                return dict
            }
        }
        return nil
    }

    // Heuristic scan to collect access/id tokens from client.server into our published properties.
    private func collectTokensFromServerIfNeeded() {
        if accessToken != nil || idToken != nil { return }
        let mirror = Mirror(reflecting: client.server)

        func inspectString(_ s: String) -> Bool {
            // try JSON extraction first
            if let token = extractTokenFromJSONString(s) {
                if isLikelyJWT(token) || token.count > 100 {
                    if accessToken == nil { accessToken = token } else if idToken == nil { idToken = token }
                    return true
                }
            }
            // try to find a JWT inside
            if let jwt = findJWTInString(s), isLikelyJWT(jwt) {
                if accessToken == nil { accessToken = jwt } else if idToken == nil { idToken = jwt }
                return true
            }
            return false
        }

        // shallow traversal
        for child in mirror.children {
            if let label = child.label?.lowercased(), let s = child.value as? String {
                if label.contains("access") && label.contains("token") {
                    if isLikelyJWT(s) || s.count > 100 { accessToken = s }
                } else if label.contains("id") && label.contains("token") {
                    if isLikelyJWT(s) || s.count > 100 { idToken = s }
                } else {
                    _ = inspectString(s)
                }
            } else {
                let desc = String(describing: child.value)
                _ = inspectString(desc)
            }
            if accessToken != nil && idToken != nil { break }
        }
    }

    // UI helper: dismiss UI (if provided) then start selection after a short delay
    func beginSelectionFromUI(dismiss: (() -> Void)? = nil, forceLogin: Bool = false) {
        // If a dismiss closure is provided, execute it on main thread to close detail view
        if let dismiss = dismiss {
            DispatchQueue.main.async { dismiss() }
        }
        // Start selection after a small delay so navigation/dismiss completes
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.30) { [weak self] in
            guard let self = self else { return }
            print("[DEBUG] OAuthManager.beginSelectionFromUI: starting selection (forceLogin=\(forceLogin))")

            // If the SDK client still thinks it's awaiting a callback, or caller asked
            // to force a login, perform an aggressive reset/recreate of the client state
            // to guarantee a fresh authorization flow.
            if self.client.awaitingAuthCallback || forceLogin {
                print("[DEBUG] OAuthManager.beginSelectionFromUI: performing aggressive client reset (forceLogin=\(forceLogin), awaiting=\(self.client.awaitingAuthCallback))")

                // Best-effort: attempt SDK abort/reset first
                self.attemptClientReset()

                // Clear local token state and Keychain
                DispatchQueue.main.async {
                    self.isAuthorized = false
                    self.accessToken = nil
                    self.idToken = nil
                    self.patientId = nil
                }
                KeychainHelper.shared.deleteToken(forKey: "accessToken")

                // Recreate client instance to ensure no stale internal state
                self.client = SMART.Client(baseURL: URL(string: FHIRConfig.baseURL)!, settings: [
                    "client_id": FHIRConfig.clientId,
                    "redirect": FHIRConfig.redirectURI,
                    "scope": FHIRConfig.scopes
                ])

                // Clear cookies and website data (best-effort)
                if let cookies = HTTPCookieStorage.shared.cookies {
                    for cookie in cookies { HTTPCookieStorage.shared.deleteCookie(cookie) }
                }
                let dataTypes = WKWebsiteDataStore.allWebsiteDataTypes()
                WKWebsiteDataStore.default().removeData(ofTypes: dataTypes, modifiedSince: Date(timeIntervalSince1970: 0)) {
                    print("[DEBUG] beginSelectionFromUI: cleared WKWebsiteDataStore")
                }

                return
            }

            // Normal path: start selection
            self.startPatientSelection()
        }
    }

}
