import Foundation
import SMART

struct PatientModel {
    let id: String
    let name: String
    let birthDate: String
    let gender: String
    
    // MARK: - Designated initializer for mock data
    init(id: String, name: String, birthDate: String, gender: String) {
        self.id = id
        self.name = name
        self.birthDate = birthDate
        self.gender = gender
    }
    
    // MARK: - FHIR Patient initializer
    init(patient: SMART.Patient) {
        self.id = patient.id?.string ?? ""
        if let name = patient.name?.first {
            let given = name.given?.compactMap { $0.string }.joined(separator: " ") ?? ""
            let family = name.family?.string ?? ""
            self.name = (given + " " + family).trimmingCharacters(in: .whitespaces)
        } else {
            self.name = ""
        }
        self.birthDate = patient.birthDate?.description ?? ""
        self.gender = patient.gender?.rawValue ?? ""
    }
}
