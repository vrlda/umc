import XCTest
@testable import UMC

final class ClientTests: XCTestCase {
    func testRegistrationPayloadIsBounded() {
        let payload = Client.registerApplicationRequest(name: "swift-test", protocolIDs: ["org.example.test/1"], resumable: true)
        XCTAssertFalse(payload.isEmpty)
        XCTAssertLessThan(payload.count, 1024)
    }
}
