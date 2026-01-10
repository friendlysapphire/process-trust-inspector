//
//  InspectorEngine.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/10/26.
//

import Foundation
import Observation

@Observable
final class InspectorEngine {
    let pid: Int32
    let processName: String
    let bundleIdentifier: String
    let execPath: String
    var refreshCount: Int = 0
    
    init() {
        self.pid = getpid()
        self.processName = ProcessInfo.processInfo.processName
        self.bundleIdentifier = Bundle.main.bundleIdentifier ?? "Unknown"
        self.execPath = Bundle.main.executablePath ?? "Unknown"
    }
    
    func refresh()
    {
        refreshCount += 1
    }

}
