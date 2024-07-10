//
//  Extensions.swift
//  TripKit
//
//  Created by Victor on 10.07.24.
//

import Foundation
import UIKit


extension UIColor {
    func toUInt32() -> UInt32 {
        var rgba: UInt32 = 0
        if let components = self.cgColor.components, components.count >= 3 {
            let r = Float(components[0])
            let g = Float(components[1])
            let b = Float(components[2])
            let a = Float(components.count >= 4 ? components[3] : 1.0)
            rgba = (UInt32(a * 255) << 24) | (UInt32(r * 255) << 16) | (UInt32(g * 255) << 8) | UInt32(b * 255)
        }
        return rgba
    }
}

extension UInt32 {
    func toRGB255() -> (red: Int, green: Int, blue: Int) {
        let red = Int((self & 0xFF0000) >> 16)
        let green = Int((self & 0x00FF00) >> 8)
        let blue = Int(self & 0x0000FF)
        return (red, green, blue)
    }
}

extension UIColor {
    func toHexString() -> String {
        var r: CGFloat = 0, g: CGFloat = 0, b: CGFloat = 0, a: CGFloat = 0
        self.getRed(&r, green: &g, blue: &b, alpha: &a)
        
        let red = Int(r * 255.0)
        let green = Int(g * 255.0)
        let blue = Int(b * 255.0)
        let alpha = Int(a * 255.0)

        return String(format: "#%02X%02X%02X%02X", alpha, red, green, blue)
    }
}
