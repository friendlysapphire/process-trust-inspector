//
//  InspectorEngine.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/10/26.
//

import Foundation
import Observation
import AppKit
import Security

@Observable
final class InspectorEngine {
    
    var runningAppList: [RunningAppRow] = []
    var selectedSnapshot: ProcessSnapshot? = nil
    var runningAppCount: Int = 0
    var refreshCount: Int = 0
    var selectedPID: pid_t = 0
    var selectionExplanationText: String = ""
    
    private func getSigningSummary(path: URL) -> SigningSummary? {
        
        // get the static code object representing the code at path.
        let cfURL = path as CFURL
        var staticCode: SecStaticCode?
        var status = SecStaticCodeCreateWithPath(cfURL,SecCSFlags(), &staticCode)
        
        guard status == errSecSuccess, let staticCode else {
            return SigningSummary(team: nil, id: nil, status: status)
        }
        
        // get the signing info from that static code object
        var signingInfo: CFDictionary?
        status = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue:kSecCSSigningInformation),          // default flags
            &signingInfo
        )
        
        guard status == errSecSuccess, let signingInfo else {
            return SigningSummary(team: nil, id: nil, status: status)
        }
        
        let info = signingInfo as NSDictionary
        
        // note: test
        print("lookng for \(kSecCodeInfoTeamIdentifier as String)")
        for i in info.allKeys {
            print(i)
        }
        // notee: /test
        
        let identifier = info[kSecCodeInfoIdentifier as String] as? String
        let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
        
        return SigningSummary(team: teamID, id: identifier, status: status)
        
    }
    
    func select(pid: pid_t) {
        
        let appList = NSWorkspace.shared.runningApplications
        
        guard let targetApp = appList.first(where: { $0.processIdentifier == pid }) else {
            // todo improve this
            print("could not find app for pid \(pid)")
            fatalError("fatal error: exiting")
        }
        
        selectedPID = pid
        let path = targetApp.executableURL
        let signingInfo: SigningSummary?
        
        if let path {
            signingInfo = self.getSigningSummary(path: path)
        } else {
            signingInfo = nil
        }
        
        selectedSnapshot = ProcessSnapshot(pPid: pid,
                                           pName: targetApp.localizedName,
                                           pBI: targetApp.bundleIdentifier,
                                           pPidPath: path,
                                           signing: signingInfo)
        
        
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
