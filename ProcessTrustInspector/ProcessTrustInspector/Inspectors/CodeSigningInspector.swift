//
//  CodeSigningInspector.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/31/26.
//

import Foundation
import Security


final class CodeSigningInspector {
    
    /// Returns a best-effort static code identity summary for the
    /// executable at the given path.
    ///
    /// Important limitations:
    /// - Inspection is performed against the on-disk binary, not the
    ///   in-memory process image.
    /// - Successful signing information does NOT imply runtime safety.
    /// - Missing fields may reflect:
    ///     - unsigned or ad-hoc signed code
    ///     - insufficient privileges
    ///     - file system access limitations
    ///     - API behavior, not properties of the target
    ///
    func getSigningSummary(path: URL) -> SigningSummary? {
        
        // get the static code object representing the code at path.
        let cfURL = path as CFURL
        var staticCode: SecStaticCode?
        var status = SecStaticCodeCreateWithPath(cfURL,SecCSFlags(), &staticCode)
        
        guard status == errSecSuccess, let staticCode else {
            
            return SigningSummary(team: nil, id: nil, certificates: nil, entitlements: nil, runtime: nil, status: status, trustCategory: .unsigned, appStorePolicyOIDEvidence: OIDEvidence.unknown(reason: "Signagure check failed"))
        }
        
        // get the signing info from that static code object
        var signingInfo: CFDictionary?
        status = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue:kSecCSSigningInformation),          // default flags
            &signingInfo
        )
        
        guard status == errSecSuccess, let signingInfo else {
            return SigningSummary(team: nil, id: nil, certificates: nil, entitlements: nil, runtime: nil, status: status, trustCategory: .unsigned, appStorePolicyOIDEvidence: OIDEvidence.unknown(reason: "Signing information unavailable."))
        }
        
        let info = signingInfo as NSDictionary
        
#if false
        
        if let tmp = info[kSecCodeInfoFlags] as? NSNumber {
            // turn it into an OptionSet
            let flags = SecCodeSignatureFlags(rawValue: tmp.uint32Value)
            print(flags.contains(SecCodeSignatureFlags.runtime))
        }
         
          
#endif
        
        let hardenedRuntime: Bool?
        
        // get hardened runtime status
        if let tmp = info[kSecCodeInfoFlags] as? NSNumber {
            let flags = SecCodeSignatureFlags(rawValue: tmp.uint32Value)
            hardenedRuntime = flags.contains(SecCodeSignatureFlags.runtime)
        } else { hardenedRuntime = nil }


        
        let certificates = info[kSecCodeInfoCertificates as String] as? [SecCertificate]
        let identifier = info[kSecCodeInfoIdentifier as String] as? String
        let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
        let entitlements = info[kSecCodeInfoEntitlementsDict] as? [String: Any]
        
        // Calculate the trust status
        let (trustCategory, oidEvidence) = evaluateTrust(
            status: status,
            teamID: teamID,
            identifier: identifier,
            certificates: certificates)
        
        
        
        return SigningSummary(team: teamID,
                              id: identifier,
                              certificates: certificates,
                              entitlements: entitlements,
                              runtime: hardenedRuntime,
                              status: status,
                              trustCategory: trustCategory,
                              appStorePolicyOIDEvidence: oidEvidence)
        
    }
    
    // OID (Object Identifier) for the "Mac App Store" Certificate Policy.
    // Presence of this OID in the leaf certificate confirms App Store origin.
    private static let appStoreOID = "1.2.840.113635.100.6.1.9"
    private static let appleTeamID = "59GAB85EFG"
    
    // MARK: - Trust Evaluation Logic
    /// Static function that takes raw signing evidence and returns a final trust category.
    private func evaluateTrust(status: OSStatus, teamID: String?, identifier: String?, certificates: [SecCertificate]?) -> (TrustCategory,OIDEvidence) {
        
        if status != 0 { return (.unsigned, OIDEvidence.unknown(reason: "Signagure check failed"))}
        
        if let team = teamID {
            // there's a team string, is it an apple team string?
            if (team == "APPLE_PLATFORM") || (team == CodeSigningInspector.appleTeamID) {
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
    private func containsAppleStoreOID(certDict:[String: Any]) -> OIDEvidence {
        
        // navigate this somewhat gross structure
        
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
            
            if let id, id == CodeSigningInspector.appStoreOID {
                return .present(oid:id)
            }
        }
        return .absent
    }
    
}

