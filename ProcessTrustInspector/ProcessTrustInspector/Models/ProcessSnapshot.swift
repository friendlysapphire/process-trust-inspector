//
//  ProcessSnapshot.swift
//  ProcessTrustInspector
//
//  Immutable, point-in-time snapshot of a running process.
//
//  A ProcessSnapshot aggregates identity, signing, provenance, and
//  execution-context metadata into a single structure suitable for
//  explanation-first analysis.
//
//  Responsibilities:
//  - Represent best-effort observations about a specific PID.
//  - Provide derived properties (sandboxing, hardened runtime, trust level)
//    without recomputing or inferring beyond available evidence.
//  - Preserve uncertainty explicitly (unknown-with-reason).
//
//  Non-responsibilities:
//  - No OS inspection logic (handled by inspectors).
//  - No UI formatting or presentation concerns.
//  - No policy decisions or security verdicts.
//
//  Notes:
//  - All fields are subject to race conditions: a process may exit or change
//    between enumeration and inspection.
//  - Missing data should be interpreted as unavailable, not suspicious.
//

import Foundation
import Security
import AppKit

/// Represents whether the process declares use of the App Sandbox.
///
/// This value is derived from the presence of the
/// `com.apple.security.app-sandbox` entitlement in the code signature.
///
/// An `unknown` result indicates that entitlement information
/// was unavailable, not that the process is unsandboxed.
enum AppSandboxStatus {
    case sandboxed
    case notSandboxed
    case unknown(reason: String)
}

/// Represents whether the executable declares use of the Hardened Runtime.
///
/// This status is inferred from code-signing flags and reflects
/// declared enforcement configuration, not observed runtime behavior.
///
/// An `unknown` result indicates that hardened runtime information
/// could not be retrieved.
enum HardenedRuntimeStatus {
    case hasHardenedRuntime
    case noHardenedRuntime
    case unknown(reason: String)
}

/// Indicates whether the executable appears to be part of an app bundle.
///
/// A bundled executable is typically located inside
/// `*.app/Contents/MacOS/`.
///
/// This classification is heuristic and may be unknown when
/// the executable path is unavailable.
enum BundledStatus {
    case bundled
    case bare
    case unknown(reason: String)
}

/// Represents the presence or absence of quarantine metadata on the executable.
///
/// Quarantine metadata is commonly applied to files downloaded
/// from external sources and influences Gatekeeper behavior.
///
/// Absence of quarantine metadata does not imply local origin
/// or safety.
enum QuarantineStatus {
    case present
    case absent
    case unknown(reason: String)
}

/// Immutable, point-in-time snapshot of a running process.
///
/// `ProcessSnapshot` aggregates identity, signing, provenance,
/// and execution-context metadata for a specific PID.
///
/// All fields are best-effort observations and may be incomplete
/// due to scope limits, missing metadata, or race conditions.
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
    let bundledStatus: BundledStatus
    let quarantineStatus: QuarantineStatus
    
    let icon: NSImage?
    
    var runningAsRoot:Bool { return uid == 0 }
    
    var isSandboxed: AppSandboxStatus {
        
        // if the structure itself is there and we have no entitlement info at all, there was an error
        guard let entitlements = signingSummary?.entitlementsDict else {
            return AppSandboxStatus.unknown(reason: "No entitlements dictionary was available in the code signature.")
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
