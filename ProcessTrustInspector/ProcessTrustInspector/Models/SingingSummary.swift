//
//  SigningSummary.swift
//  ProcessTrustInspector
//  Created by Aaron Weiss on 1/31/26.
//
//
//  Represents a best-effort summary of static code-signing
//  identity for an on-disk executable.
//
//  This data is derived from Security.framework inspection
//  of the executable file and does not prove runtime behavior.

import Foundation
import Security

/// Models the 4 foundational code signature types.
/// This abstraction simplifies macOS app security foundations into
/// categories that are meaningful to a non-technical user.
enum TrustCategory {
    case apple      // Signed by Apple (OS Component)
    case appStore   // Signed by Apple (App Store Distribution)
    case developer  // Signed by Developer ID (Direct Distribution)
    case unsigned   // Ad-hoc or Broken Signature
    
    var displayName: String {
        switch self {
        case .apple:
            return "Apple Software"
        case .appStore:
            return "3rd Party App Store Software"
        case .developer:
            return "3rd Party, Non-App Store Software"
        case .unsigned:
            return "Unsigned / Untrusted"
        }
    }
}

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

enum EntitlementsEvidence {
    case present
    case absent
    case unknown(reason: String)
}
    

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

