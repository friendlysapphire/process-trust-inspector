//
//  ProcessSnapshot.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/31/26.
//

import Foundation
import Security


struct ProcessSnapshot {
    let pid: pid_t
    let uid: pid_t
    let parentPid: pid_t?
    let parentPidName: String?
    let name: String?
    let startTime: Date?
    let bundleIdentifier: String?
    let executablePath: URL?
    let signingSummary: SigningSummary?
    
    var runningAsRoot:Bool { return uid == 0 }
    
    var trustLevel: TrustCategory {
        return signingSummary?.trustCategory ?? .unsigned
    }
    
}
