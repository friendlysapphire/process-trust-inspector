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
/// This abstraction simplifies the complex reality of macOS security into
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

struct SigningSummary {
    let teamID: String?
    let identifier: String?
    let certificates: [SecCertificate]?
    let entitlements: [String: Any]?
    let appStorePolicyOIDEvidence: OIDEvidence
    let status: OSStatus
    let hardenedRuntime: Bool?
    

    // computed trust level struct
    let trustCategory: TrustCategory
    
    // OID (Object Identifier) for the "Mac App Store" Certificate Policy.
    // Presence of this OID in the leaf certificate confirms App Store origin.
    private static let appStoreOID = "1.2.840.113635.100.6.1.9"
    private static let appleTeamID = "59GAB85EFG"
    
    init(team: String?, id: String?, certificates: [SecCertificate]?, entitlements: [String: Any]?, runtime: Bool?, status: OSStatus) {
        self.teamID = team
        self.identifier = id
        self.status = status
        self.entitlements = entitlements
        self.certificates = certificates
        self.hardenedRuntime = runtime
        
        // Calculate the trust trust status
        (self.trustCategory,self.appStorePolicyOIDEvidence) = SigningSummary.evaluateTrust(
            status: status,
            teamID: team,
            identifier: id,
            certificates: certificates)
    }
    
    // MARK: - Trust Evaluation Logic
    /// Static function that takes raw signing evidence and returns a final trust category.
    private static func evaluateTrust(status: OSStatus, teamID: String?, identifier: String?, certificates: [SecCertificate]?) -> (TrustCategory,OIDEvidence) {
        
        if status != 0 { return (.unsigned, OIDEvidence.unknown(reason: "Signagure check failed"))}
        
        if let team = teamID {
            // there's a team string, is it an apple team string?
            if (team == "APPLE_PLATFORM") || (team == appleTeamID) {
                return (.apple, OIDEvidence.absent)
            } else {
                // there's a team string but it doesn't look like an Apple string
                // it's 3rd party and either app store or not app store. look at the certs
                // to distinguish
                guard let certs = certificates, !certs.isEmpty else {
                    return (.unsigned,OIDEvidence.unknown(reason:"Certificate information was unavailable for inspection."))
                }
                // grab the leaf node cert
                // TODO: consider optimizing fn call by pulling out "2.5.29.32" (as CFString) here
                // TODO: and just passing that in. with copy on write, not sure if that gets is anything rn
                let certInfo = SecCertificateCopyValues(certs[0],nil,nil)
                
                if let cd = certInfo as? [String: Any] {
                    // extract the relevant cert string
                    let evidence = containsAppleStoreOID(certDict: cd)
                    
                    switch evidence {
                    case .present:
                        return (.appStore, evidence)
                    case .absent, .unknown:
                        return (.developer, evidence)
                    }
                }
 
                // fall through. we know we have a valid sig and team but couldn't find
                // app store origin evidence.
                return (.developer,OIDEvidence.absent)
            }
        } else {
            // there's no team string, so it's either ad hoc (eg local dev, considered 'unsigned') or appl
            if let id = identifier, id.hasPrefix("com.apple") {
                return (.apple, OIDEvidence.absent)
            }
            
            return (.unsigned,OIDEvidence.absent)
        }
    }
    
    /// Parses the certificate dictionary to check if the App Store OID is present.
    /// Returns true if found, false otherwise.
    private static func containsAppleStoreOID(certDict:[String: Any]) -> OIDEvidence {
        
        // get the "Certificate Policies" extension section
        let certPolicies = certDict["2.5.29.32"] as? [String : Any]
        
        guard let certPolicies, !certPolicies.isEmpty else {
            return .unknown(reason: "Certificate policies extension unavailable")
        }
        
        // get the list of policies inside that extension
        let certPolicyLists = certPolicies[kSecPropertyKeyValue as String] as? [[String : Any]]
        
        guard let certPolicyLists, !certPolicyLists.isEmpty else {
            return .unknown(reason: "Certificate policy list unavailable")
        }
        
        // iterate through all policies to find the App Store OID
        for d in certPolicyLists {
            
            let id = d[kSecPropertyKeyValue as String] as? String
            
            if let id, id == appStoreOID {
                return .present(oid:id)
            }
        }
        return .absent
    }
}
