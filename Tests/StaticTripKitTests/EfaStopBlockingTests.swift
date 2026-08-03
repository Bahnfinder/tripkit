import XCTest
import SwiftyJSON
@testable import TripKit

class EfaStopBlockingTests: XCTestCase {

    private let provider = VrrProvider()

    func testStopBlockingMatchesMentionedLine() throws {
        let json = try JSON(data: stopFinderResponse(infoType: "stopBlocking", text: "Lines 4 and 911 are diverted at this stop."))
        let line = Line(id: nil, network: nil, product: .bus, label: "4")

        XCTAssertTrue(provider.stopFinderResponseHasStopBlocking(json: json, line: line))
    }

    func testStopBlockingIgnoresOtherLines() throws {
        let json = try JSON(data: stopFinderResponse(infoType: "stopBlocking", text: "Lines 4 and 911 are diverted at this stop."))
        let line = Line(id: nil, network: nil, product: .bus, label: "929")

        XCTAssertFalse(provider.stopFinderResponseHasStopBlocking(json: json, line: line))
    }

    func testStopInfoDoesNotCountAsStopBlocking() throws {
        let json = try JSON(data: stopFinderResponse(infoType: "stopInfo", text: "Linie 4: Haltestellenausfall. Die Haltestelle Rheinkamper Ring wird nicht angefahren."))
        let line = Line(id: nil, network: nil, product: .bus, label: "4")

        XCTAssertFalse(provider.stopFinderResponseHasStopBlocking(json: json, line: line))
    }

    private func stopFinderResponse(infoType: String, text: String) -> Data {
        """
        {
          "stopFinder": {
            "points": {
              "point": {
                "infos": {
                  "info": {
                    "paramList": {
                      "param": [
                        { "name": "infoType", "value": "\(infoType)" }
                      ]
                    },
                    "infoText": {
                      "content": "<b>\(text)</b>",
                      "additionalText": "Die beschriebenen Aenderungen sind in der elektronischen Fahrplanauskunft nicht beruecksichtigt."
                    }
                  }
                }
              }
            }
          }
        }
        """.data(using: .utf8)!
    }
}
