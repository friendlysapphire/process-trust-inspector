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
    
    var explanation: String {
        switch self {
        case .apple:
            return "This is signed by Apple and part of the macOS operating system."
        case .appStore:
            return "This app was reviewed by Apple and is sandboxed for security."
            // TODO: developer mat or may not be sandboxed -- figure this out and give the
            // TODO: correct answer
        case .developer:
            return "This app is signed by a known developer, but has not been reviewed by Apple."
        case .unsigned:
            return "This code has no valid signature. macOS cannot verify who created it."
        }
    }
}

struct SigningSummary {
    let teamID: String?
    let identifier: String?
    let certificates: [SecCertificate]?
    let status: OSStatus
    
    // computed trust level struct
    let trustCategory: TrustCategory
    
    // OID (Object Identifier) for the "Mac App Store" Certificate Policy.
    // Presence of this OID in the leaf certificate confirms App Store origin.
    private static let appStoreOID = "1.2.840.113635.100.6.1.9"
    private static let appleTeamID = "59GAB85EFG"
    
    init(team: String?, id: String?, certificates: [SecCertificate]?, status: OSStatus) {
        self.teamID = team
        self.identifier = id
        self.status = status
        self.certificates = certificates
        
        // Calculate the trust verdict immediately
        self.trustCategory = SigningSummary.evaluateTrust(
            status: status,
            teamID: team,
            identifier: id,
            certificates: certificates)
    }
    
    // MARK: - Trust Evaluation Logic
    /// Static function that takes raw signing evidence and returns a final trust category.
    private static func evaluateTrust(status: OSStatus, teamID: String?, identifier: String?, certificates: [SecCertificate]?) -> TrustCategory {
        
        if status != 0 { return .unsigned }
        
        if let team = teamID {
            // there's a team string, is it an apple team string?
            if (team == "APPLE_PLATFORM") || (team == appleTeamID) {
                return .apple
            } else {
                // there's a team string but it doesn't look like an Apple string
                // it's 3rd party and either app store or not app store. look at the certs
                // to distinguish
                guard let certs = certificates, !certs.isEmpty else {
                    return .unsigned
                }
                // grab the leaf node cert
                // TODO: consider optimizing fn call by pulling out "2.5.29.32" (as CFString) here
                // TODO: and just passing that in.
                let certInfo = SecCertificateCopyValues(certs[0],nil,nil)
                
                if let cd = certInfo as? [String: Any] {
                    // extract the relevant cert string
                    if containsAppleStoreOID(certDict: cd) { return .appStore }
                }
                // fall through. we know we have a valid sig and team but couldn't find
                // app store origin evidence.
                return .developer
            }
        } else {
            // there's no team string, so it's either ad hoc (eg local dev, considered 'unsigned') or appl
            if let id = identifier, id.hasPrefix("com.apple") {
                return .apple
            }
            
            return .unsigned
        }
    }
    
    /// Parses the certificate dictionary to check if the App Store OID is present.
    /// Returns true if found, false otherwise.
    private static func containsAppleStoreOID(certDict:[String: Any]) -> Bool {
        
        // get the "Certificate Policies" extension section
        let certPolicies = certDict["2.5.29.32"] as? [String : Any]
        
        guard let certPolicies, !certPolicies.isEmpty else { return false }
        
        // get the list of policies inside that extension
        let certPolicyLists = certPolicies[kSecPropertyKeyValue as String] as? [[String : Any]]
        
        guard let certPolicyLists, !certPolicyLists.isEmpty else { return false }
        
        // iterate through all policies to find the App Store OID
        for d in certPolicyLists {
            
            let id = d[kSecPropertyKeyValue as String] as? String
            
            if let id, id == appStoreOID {
                return true
            }
        }
        return false
    }
}
