//
//  ContentView.swift
//  SMARTFHIRDemo
//
//  Created by Edward Lo on 2026/2/6.
//

import SwiftUI
import SMART

struct ContentView: View {
    @EnvironmentObject var oauthManager: OAuthManager
    @StateObject private var patientViewModel: PatientViewModel

    @State private var navigateToDetail = false

    // Default initializer used by app runtime
    init() {
        _patientViewModel = StateObject(wrappedValue: PatientViewModel(fhirService: FHIRService(client: Client(
            baseURL: URL(string: FHIRConfig.baseURL)!,
            settings: [
                "client_id": FHIRConfig.clientId,
                "redirect": FHIRConfig.redirectURI,
                "scope": FHIRConfig.scopes
            ]
        ))))
    }

    // Test / Preview initializer allowing injection of a pre-configured view model
    init(previewViewModel: PatientViewModel) {
        _patientViewModel = StateObject(wrappedValue: previewViewModel)
    }

    var body: some View {
        NavigationStack {
            VStack(spacing: 24) {
                if oauthManager.isAuthorized {
                    if let patientId = oauthManager.patientId {
                        // Debug: 顯示 patientId
                        Text("Patient ID: \(patientId)")
                            .font(.caption)
                            .foregroundColor(.gray)
                            .padding(.bottom, 4)
                        // 自動載入病患資料
                        if patientViewModel.patient == nil && patientViewModel.error == nil {
                            ProgressView("載入中...")
                                .onAppear {
                                    patientViewModel.loadPatient(patientId: patientId)
                                }
                        }
                    } else {
                        // OAuth succeeded but no patient id was provided by the server.
                        // Show a clear message and let the user retry or sign out so they can re-select.
                        VStack(spacing: 12) {
                            Text("未選擇病患或授權回應未包含病患 ID。請重新選擇病患或登出後再試一次。")
                                .multilineTextAlignment(.center)
                                .foregroundColor(.secondary)
                                .padding(.bottom, 8)

                            HStack(spacing: 16) {
                                Button("重新選擇病患") {
                                    // Force the IdP to show the login / patient selection UI
                                    oauthManager.forceReauthorize()
                                }

                                Button("登出") {
                                    // Perform a full logout that clears keychain, tokens, and
                                    // resets the underlying client state.
                                    oauthManager.logout()
                                }
                                .tint(.red)
                            }
                        }
                        .padding()
                        .frame(maxWidth: .infinity)
                    }

                    if let patient = patientViewModel.patient {
                        // If patient loaded, show a summary and trigger navigation
                        VStack(alignment: .leading, spacing: 8) {
                            Text("病患：\(patient.name)")
                                .font(.headline)
                            Text("生日：\(patient.birthDate)")
                                .font(.subheadline)
                        }
                        .onAppear {
                            // Auto-navigate when the patient appears
                            DispatchQueue.main.async {
                                self.navigateToDetail = true
                            }
                        }
                    } else if let error = patientViewModel.error {
                        Text("資料載入失敗: \(error.localizedDescription)")
                            .foregroundColor(.red)
                    }
                } else {
                    LoginView()
                }
            }
            .padding()
            .navigationTitle("SMART FHIR")
            // Present patient detail when navigateToDetail becomes true
            .navigationDestination(isPresented: $navigateToDetail) {
                if let patient = patientViewModel.patient {
                    PatientDetailView(patient: patient)
                } else {
                    EmptyView()
                }
            }
            .onReceive(patientViewModel.$patient) { newPatient in
                // Keep navigateToDetail in sync with whether a patient exists.
                // This ensures clearing the patient will also dismiss the detail view
                // and prevent it from immediately re-presenting.
                navigateToDetail = (newPatient != nil)
            }
        }
        .environmentObject(patientViewModel)
    }
}

//#if DEBUG
//struct ContentView_Previews: PreviewProvider {
//    static var previews: some View {
//        NavigationStack {
//            PatientDetailView(patient: PatientModel(
//                id: "12345",
//                name: "王小明",
//                birthDate: "1990-01-01",
//                gender: "male"
//            ))
//        }
//    }
//}
//#endif

#Preview("Unauthorized - Login") {
    ContentView(previewViewModel: PatientViewModel(mockPatient: nil))
        .environmentObject({
            let oauth = OAuthManager()
            oauth.isAuthorized = false
            oauth.patientId = nil
            return oauth
        }())
}

#Preview("Authorized - Loading") {
    ContentView(previewViewModel: PatientViewModel(mockPatient: nil))
        .environmentObject({
            let oauth = OAuthManager()
            oauth.isAuthorized = true
            oauth.patientId = "12345"
            return oauth
        }())
}

#Preview("Authorized - Loaded") {
    ContentView(previewViewModel: PatientViewModel(mockPatient: PatientModel(id: "12345", name: "王小明", birthDate: "1990-01-01", gender: "male")))
        .environmentObject({
            let oauth = OAuthManager()
            oauth.isAuthorized = true
            oauth.patientId = "12345"
            return oauth
        }())
}
