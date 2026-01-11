//
//  InspectorEngine.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/10/26.
//

import Foundation
import Observation
import AppKit

@Observable
final class InspectorEngine {
    let pid: Int32
    let processName: String
    let bundleIdentifier: String
    let execPath: String
    var refreshCount: Int = 0
    var runningAppCount: Int
    var firstRunningApp: String
    
    init() {
        self.pid = getpid()
        self.processName = ProcessInfo.processInfo.processName
        self.bundleIdentifier = Bundle.main.bundleIdentifier ?? "Unknown"
        self.execPath = Bundle.main.executablePath ?? "Unknown"
        self.runningAppCount = 0
        self.firstRunningApp = "Unknown"
        refresh()
    }
    
    func refresh()
    {
        refreshCount += 1
        self.runningAppCount =
            NSWorkspace.shared.runningApplications.count
        self.firstRunningApp =
            NSWorkspace.shared.runningApplications.first?.localizedName ?? "Unknown"
    }

}
