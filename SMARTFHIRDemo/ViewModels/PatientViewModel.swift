import Foundation
import SMART
import Combine

class PatientViewModel: ObservableObject {
    @Published var patient: PatientModel?
    @Published var error: Error?
    var fhirService: FHIRService

    init(fhirService: FHIRService) {
        self.fhirService = fhirService
    }

    // Preview / test friendly initializer: creates a default FHIRService and
    // optionally seeds a mock patient so previews don't trigger network.
    convenience init(mockPatient: PatientModel?) {
        let client = Client(
            baseURL: URL(string: FHIRConfig.baseURL)!,
            settings: [
                "client_id": FHIRConfig.clientId,
                "redirect": FHIRConfig.redirectURI,
                "scope": FHIRConfig.scopes
            ]
        )
        let service = FHIRService(client: client)
        self.init(fhirService: service)
        if let p = mockPatient {
            self.patient = p
            self.error = nil
        }
    }

    func loadPatient(patientId: String) {
        fhirService.fetchPatient(patientId: patientId) { [weak self] patient, error in
            DispatchQueue.main.async {
                if let patient = patient {
                    self?.patient = PatientModel(patient: patient)
                    self?.error = nil
                } else {
                    self?.patient = nil
                    self?.error = error
                }
            }
        }
    }
}
