//
//  SMARTFHIRDemoApp.swift
//  SMARTFHIRDemo
//
//  Created by Edward Lo on 2026/2/6.
//

import SwiftUI

@main
struct SMARTFHIRDemoApp: App {
    @StateObject private var oauthManager = OAuthManager()
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(oauthManager)
                .onOpenURL { url in
                    // Ensure redirect URLs are forwarded to the OAuth manager
                    oauthManager.handleRedirect(url: url)
                }
        }
    }
}
