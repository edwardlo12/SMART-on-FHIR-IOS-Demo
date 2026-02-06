import SwiftUI

struct LoginView: View {
    @EnvironmentObject var oauthManager: OAuthManager
    @State private var isLoading = false
    @State private var errorMessage: String?
    
    var body: some View {
        VStack(spacing: 24) {
            Text("SMART on FHIR 授權示範")
                .font(.title)
                .padding(.top, 40)
            Button(action: {
                isLoading = true
                oauthManager.authorize { success, error in
                    isLoading = false
                    if let error = error {
                        errorMessage = error.localizedDescription
                    }
                }
            }) {
                Text(isLoading ? "授權中..." : "連接 FHIR Server")
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.accentColor)
                    .foregroundColor(.white)
                    .cornerRadius(8)
            }
            if let errorMessage = errorMessage {
                Text(errorMessage)
                    .foregroundColor(.red)
            }
        }
        .padding()
    }
}
