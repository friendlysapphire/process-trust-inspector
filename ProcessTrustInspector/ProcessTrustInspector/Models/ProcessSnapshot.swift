//
//  ProcessSnapshot.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/31/26.
//

import Foundation
import Security

enum AppSandboxStatus {
    case sandboxed
    case notSandboxed
    case unknown(reason: String)
}

enum HardenedRuntimeStatus {
    case hasHardenedRuntime
    case noHardenedRuntime
    case unknown(reason: String)
}

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
    
    var isSandboxed: AppSandboxStatus {
        
        // if the structure itself is there and we have no entitlement info at all, there was an error
        guard let entitlements = signingSummary?.entitlements else {
            return AppSandboxStatus.unknown(reason: "Unable to retrieve entitlements data structure for this process.")
        }
        
        let sboxed = entitlements["com.apple.security.app-sandbox"] as? Bool ?? false
        return sboxed ? .sandboxed : .notSandboxed
    }
    
    var hasHardenedRuntime: HardenedRuntimeStatus {
        
        guard let rt = signingSummary?.hardenedRuntime else {
            return .unknown(reason: "Unable to retrieve hardened runtime information for this process.")
        }
        
        return rt ? .hasHardenedRuntime : .noHardenedRuntime
       
    }
    
    var trustLevel: TrustCategory {
        return signingSummary?.trustCategory ?? .unsigned
    }
    
}
