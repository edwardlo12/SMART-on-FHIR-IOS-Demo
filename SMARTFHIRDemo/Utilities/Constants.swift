//
//  Constants.swift
//  SMARTFHIRDemo
//
//  Created by Edward Lo on 2026/2/6.
//

// 定義 FHIR 伺服器設定
struct FHIRConfig {
    static let baseURL = "https://launch.smarthealthit.org/v/r4/sim/WzIsIiIsIiIsIkFVVE8iLDAsMCwwLCIiLCIiLCIiLCIiLCIiLCIiLCIiLDAsMSwiIl0/fhir"
    static let clientId = "your_client_id" // 請替換為實際 client id
    static let redirectURI = "mysmartapp://callback"
    static let scopes = "launch/patient patient/*.read openid fhirUser"
    // Optional OpenID Connect endpoints - fill if known for your IdP
    // If discoveryURL is provided, the SDK will attempt to fetch discovery
    // to locate revocation and end_session endpoints automatically.
    // Derive SMART discovery from the FHIR base. SMART servers typically expose
    // their configuration at {FHIR_BASE}/.well-known/smart-configuration
    static let discoveryURL: String? = baseURL + "/.well-known/smart-configuration"
    static let revocationEndpoint: String? = nil // e.g. "https://idp.example/oauth/revoke"
    static let endSessionEndpoint: String? = nil // e.g. "https://idp.example/oauth/end_session"
    static let postLogoutRedirect: String? = nil // e.g. "mysmartapp://post-logout"
}
