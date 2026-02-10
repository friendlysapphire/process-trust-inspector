//
//  SigningSummary.swift
//  ProcessTrustInspector
//
//  Best-effort summary of static code-signing identity for an on-disk executable.
//
//  Responsibilities:
//  - Carry Security.framework-derived signing metadata for a file path.
//  - Preserve uncertainty explicitly (unknown-with-reason) where inspection is incomplete.
//  - Provide a simplified, UI-friendly trust classification (TrustCategory).
//
//  Non-responsibilities:
//  - Does not prove runtime behavior.
//  - Does not perform Gatekeeper / notarization assessment.
//  - Does not interpret “safety” or make verdicts.
//
//  Notes:
//  - Most fields originate from SecCodeCopySigningInformation / related Security APIs.
//  - Unknown values are expected in normal operation and should be interpreted as unavailable,
//    not suspicious.
//

import Foundation
import Security

/// Simplified code-signing identity categories intended for non-technical users.
/// These categories describe *static code-signing identity*for the on-disk executable,
/// not runtime behavior or “safety.”
enum TrustCategory {
    case apple      // Signed by Apple (OS Component)
    case appStore   // Signed by Apple (App Store Distribution)
    case developer  // Signed by Developer ID (Direct Distribution)
    case unsigned   // No publisher identity (Ad-hoc or unsigned)
    case unknown    // something failed
    
    var displayName: String {
        switch self {
        case .apple:
            return "Apple Software"
        case .appStore:
            return "3rd Party App Store Software"
        case .developer:
            return "3rd Party, Non-App Store Software"
        case .unsigned:
            return "Unsigned or Ad-hoc (No Publisher Identity)"
        case .unknown:
            return "Signature check failed"
        }
    }
}

/// Evidence for presence/absence of the App Store certificate policy OID in signing certificates.
enum OIDEvidence {
    
    case present(oid: String)
    case absent
    case unknown(reason: String)
    
    var oid: String? {
        switch self {
        case .present(let oid):
            return oid
        case .absent, .unknown:
            return nil
        }
    }
}

/// Whether entitlements appear to exist for the code signature (best-effort).
enum EntitlementsEvidence {
    case present
    case absent
    case unknown(reason: String)
}
    
/// Best-effort summary of signing-related metadata for an on-disk executable.
struct SigningSummary {
    let teamID: String?
    let identifier: String?
    let certificates: [SecCertificate]?
    let entitlementsDict: [String: Any]?
    let appStorePolicyOIDEvidence: OIDEvidence
    let status: OSStatus
    let hardenedRuntime: Bool?
    let entitlementsEvidence: EntitlementsEvidence
    

    // computed trust level struct
    let trustCategory: TrustCategory
    
    init(team: String?, id: String?, certificates: [SecCertificate]?, entitlements: [String: Any]?, runtime: Bool?, status: OSStatus, trustCategory: TrustCategory, appStorePolicyOIDEvidence: OIDEvidence, entitlementsEvidence: EntitlementsEvidence) {
        self.teamID = team
        self.identifier = id
        self.status = status
        self.entitlementsDict = entitlements
        self.certificates = certificates
        self.hardenedRuntime = runtime
        self.trustCategory = trustCategory
        self.appStorePolicyOIDEvidence = appStorePolicyOIDEvidence
        self.entitlementsEvidence = entitlementsEvidence
    }
}

