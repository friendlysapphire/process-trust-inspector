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
    var runningAppsListText: String
    
    init() {
        // one-time use inits
        self.pid = getpid()
        self.processName = ProcessInfo.processInfo.processName
        self.bundleIdentifier = Bundle.main.bundleIdentifier ?? "Error"
        self.execPath = Bundle.main.executablePath ?? "Error"
        self.runningAppCount = 0
        self.firstRunningApp = "Error"
        self.runningAppsListText = "Error"
        // init mutable vars
        refresh()
    }
    
    func refresh()
    {
        refreshCount += 1
        
        self.runningAppCount =
            NSWorkspace.shared.runningApplications.count
        
        self.firstRunningApp =
            NSWorkspace.shared.runningApplications.first?.localizedName ?? "Unknown"
        
        // set runningAppsText : name (pid) for each running app.
        // note: evolve this to use map, join, etc...
        var names = ""
        let appList = NSWorkspace.shared.runningApplications
        
        for app in appList {
            let name = app.localizedName ?? "Unknown"
            let pid = app.processIdentifier
            // note: final entry will get \n. could snip it.
            names += "\(name) (\(pid))\n"
        }
        
        self.runningAppsListText = names
    }
    

}
