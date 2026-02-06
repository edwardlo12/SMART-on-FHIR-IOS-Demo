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
    // 處理 URL callback (legacy; kept for reference)
    func application(_ app: UIApplication, open url: URL, options: [UIApplication.OpenURLOptionsKey : Any] = [:]) -> Bool {
        oauthManager.handleRedirect(url: url)
        return true
    }
}
