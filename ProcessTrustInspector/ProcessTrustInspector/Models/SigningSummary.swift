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

/// Simplified static code-signing identity categories.
///
/// These categories describe the *publisher identity* established
/// by the code signature on the on-disk executable.
///
/// They do not describe runtime behavior, safety, notarization,
/// or whether the software should be trusted to execute.
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

/// Evidence for the presence or absence of a specific certificate policy OID.
///
/// In v1, this is used to detect the Mac App Store distribution policy
/// by inspecting certificate policy extensions.
///
/// An `unknown` result indicates that certificate inspection was
/// incomplete or unavailable, not that the policy is absent.
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

/// Indicates whether entitlement data appears to exist in the code signature.
///
/// This reflects whether entitlements were observed in signing metadata,
/// not whether any entitlements were granted, enforced, or exercised
/// at runtime.
enum EntitlementsEvidence {
    case present
    case absent
    case unknown(reason: String)
}
    
/// Best-effort summary of static code-signing metadata for an executable.
///
/// `SigningSummary` represents identity and configuration information
/// derived from Security.framework inspection of the on-disk binary.
///
/// All fields are best-effort and may be incomplete due to:
/// - unsigned or ad-hoc signed code
/// - insufficient privileges
/// - missing certificate metadata
/// - API or file-system limitations
///
/// This structure does not describe runtime memory state, behavior,
/// or safety.
struct SigningSummary {
    let teamID: String?
    let identifier: String?
    let certificates: [SecCertificate]?
    let entitlementsDict: [String: Any]?
    let appStorePolicyOIDEvidence: OIDEvidence
    let status: OSStatus
    let hardenedRuntime: Bool?
    let entitlementsEvidence: EntitlementsEvidence
    

    //// Final, simplified trust category derived from signing metadata.
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

