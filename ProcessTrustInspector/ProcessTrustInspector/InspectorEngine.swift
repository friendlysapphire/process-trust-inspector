//
//  InspectorEngine.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/10/26.
//

import Foundation
import Observation
import AppKit

struct RunningAppRow: Identifiable {
    let id: pid_t
    let pPid: pid_t
    let pName: String?
    let pBundleIdentifier: String?
    
    init(pPid:pid_t = 0, pName:String?, pBI:String?) {
        self.pPid = pPid
        self.id = pPid
        self.pName = pName
        self.pBundleIdentifier = pBI
    }
}

@Observable
final class InspectorEngine {
    
    var runningAppList: [RunningAppRow] = []
    var runningAppCount: Int = 0
    var refreshCount: Int = 0
    
    init() {
        refresh()
    }
    
    func refresh()
    {
        refreshCount += 1
        runningAppList = []
        
        self.runningAppCount =
        NSWorkspace.shared.runningApplications.count

        let appList = NSWorkspace.shared.runningApplications
        
        for app in appList {
            
            let newApp = RunningAppRow(pPid: app.processIdentifier,
                                       pName: app.localizedName,
                                       pBI:app.bundleIdentifier)
            
            runningAppList.append(newApp)
        }
        runningAppCount = runningAppList.count
    }
}
