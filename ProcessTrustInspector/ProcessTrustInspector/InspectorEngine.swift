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

struct ProcessSnapshot {
    let pPid: pid_t
    let pName: String?
    let pBundleIdentifier: String?
    let pExecutablePath: URL?
    
    init(pPid:pid_t, pName:String?, pBI:String?, pPidPath:URL?) {
        self.pPid = pPid
        self.pName = pName
        self.pBundleIdentifier = pBI
        self.pExecutablePath = pPidPath
        
        /*TODO: use proc_pidpath (libproc.h) to capture non-GUI apps. note: looks like it requires C buffer + withUnsafeMutableBufferPointer bridge. */
    }
    
}

@Observable
final class InspectorEngine {
    
    var runningAppList: [RunningAppRow] = []
    var selectedSnapshot: ProcessSnapshot? = nil
    var runningAppCount: Int = 0
    var refreshCount: Int = 0
    var selectedPID: pid_t = 0
    var selectionExplanationText: String = ""
    
    func select(pid: pid_t) {

        let appList = NSWorkspace.shared.runningApplications
        
        guard let targetApp = appList.first(where: { $0.processIdentifier == pid }) else {
            print("could not find app for pid \(pid)")
            fatalError("fatal error: exiting")
        }
        
        selectedPID = pid
        selectedSnapshot = ProcessSnapshot(pPid: pid,
                                           pName: targetApp.localizedName,
                                           pBI: targetApp.bundleIdentifier,
                                           pPidPath: targetApp.executableURL)
        
        
        selectionExplanationText = """
            \u{2022} This is a best-effort identity snapshot for the selected process.
            \u{2022} PID identifies a running instance.
            \u{2022} Bundle ID only exists for bundled apps.
            \u{2022} Executable path tells you what binary is running and is the starting point for code-signing/trust checks.
            \u{2022} Missing fields are normal.
            """
    }
    
    init() {
        refresh()
    }
    
    func refresh() {
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
