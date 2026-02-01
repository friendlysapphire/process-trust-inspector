//
//  ProcessSnapshot.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/31/26.
//

import Foundation
import Security


struct ProcessSnapshot {
    let pPid: pid_t
    let pUid: pid_t
    let pParentPid: pid_t?
    let pParentPidName: String?
    let pName: String?
    let pStartTime: Date?
    let pBundleIdentifier: String?
    let pExecutablePath: URL?
    let pSigningSummary: SigningSummary?
    
    var runningAsRoot:Bool { pUid == 0 ? true : false }
}
