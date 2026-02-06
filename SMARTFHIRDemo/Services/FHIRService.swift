import Foundation
import SMART
import Combine

class FHIRService: ObservableObject {
    var client: Client
    // 若有需要可加上 publisher
    // let objectWillChange = ObservableObjectPublisher()    self.client = client
    
    init(client: Client) {
        self.client = client
    }
    
    func fetchPatient(patientId: String, completion: @escaping (SMART.Patient?, Error?) -> Void) {
        SMART.Patient.read(patientId, server: client.server) { resource, error in
            completion(resource as? SMART.Patient, error)
        }
    }
}
