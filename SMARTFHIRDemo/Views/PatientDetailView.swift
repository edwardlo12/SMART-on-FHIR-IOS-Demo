import SwiftUI

struct PatientDetailView: View {
    let patient: PatientModel
    // Optional callback if parent wants to handle "back" action manually
    var onBack: (() -> Void)? = nil
    @Environment(\.dismiss) private var dismiss
    @EnvironmentObject private var oauthManager: OAuthManager
    @EnvironmentObject private var patientViewModel: PatientViewModel
    
    var body: some View {
        GeometryReader { geometry in
            // Use a ScrollView so content can expand on small screens
            ScrollView {
                VStack(alignment: .leading, spacing: 16) {
                    Text("病患詳細資料")
                        .font(.headline)
                    Text("姓名: \(patient.name)")
                    Text("生日: \(patient.birthDate)")
                    Text("性別: \(patient.gender)")
                    Text("ID: \(patient.id)")
                    Spacer(minLength: 0)
                }
                .padding()
                // Make the VStack at least as tall as the available space so
                // Spacer() can push content to the top and the card fills the view.
                .frame(maxWidth: .infinity, minHeight: geometry.size.height, alignment: .topLeading)
//                .background(Color(UIColor.systemGray6))
//                .cornerRadius(12)
                .padding() // outer padding to the scroll view
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .navigationTitle("病患")
        // hide default back button so our toolbar button is used consistently
        .navigationBarBackButtonHidden(true)
        .toolbar {
            ToolbarItem(placement: .navigationBarLeading) {
                Button(action: {
                    // Dismiss first to avoid navigation race where clearing state
                    // while the view is still presented causes a blank/unresponsive view.
                    if let onBack = onBack {
                        onBack()
                    } else {
                        dismiss()
                    }
                    
                    // After a short delay (allow dismiss animation to complete), clear state
                    // and allow the main view to show reselect/logout UI.
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.30) {
                        print("[DEBUG] PatientDetailView: back action clearing patient and patientId")
                        patientViewModel.patient = nil
                        patientViewModel.error = nil
                        oauthManager.patientId = nil
                    }
                }) {
                    HStack(spacing: 6) {
                        Image(systemName: "chevron.left")
                    }
                }
            }
            // Provide an explicit action to change the selected patient.
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("重新選病患") {
//                    use func reselectPatient()
                }
             }
         }
     }
 }
 
 #Preview {
    NavigationStack {
        PatientDetailView(patient: PatientModel(
            id: "12345",
            name: "王小明",
            birthDate: "1990-01-01",
            gender: "male"
        ))
        .environmentObject(OAuthManager())
        .environmentObject(PatientViewModel(mockPatient: PatientModel(id: "12345", name: "王小明", birthDate: "1990-01-01", gender: "male")))
    }
}
