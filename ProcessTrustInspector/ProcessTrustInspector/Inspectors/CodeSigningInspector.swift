//
//  CodeSigningInspector.swift
//  Process Trust Inspector
//
//  Purpose:
//  Inspects static code-signing metadata for on-disk executables.
//
//  Responsibilities:
//  - Queries Security.framework for signing information
//  - Extracts identity, entitlements, and policy evidence
//  - Produces raw inputs for trust classification
//
//  Non-Responsibilities:
//  - Making safety judgments or verdicts
//  - Explaining results to users
//
//  Notes:
//  - Inspection is static and does not reflect runtime memory state
//  - Failures are expected and must be handled by callers
//

import Foundation
import Security



// TODO: signing inspection path conflates “unsigned” with “inspection unavailable” in some failure cases.
// (SecStaticCodeCreateWithPath fails, SecCodeCopySigningInformation fails)
// probably means adding .unknown(str) to TC enum
// Revisit in cleanup to v1 release


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
            //SecStaticCodeCreateWithPath reports failure
            return SigningSummary(team: nil, id: nil, certificates: nil, entitlements: nil, runtime: nil,
                                  status: status, trustCategory: .unknown, appStorePolicyOIDEvidence: OIDEvidence.unknown(reason: "Signagure check failed"),
                                  entitlementsEvidence: EntitlementsEvidence.unknown(reason: "Signature check failed"))
        }
        
        // get the signing info from that static code object
        var signingInfo: CFDictionary?
        
        // NOTE: rawValue:kSecCSSigningInformation used below because apparently there's no SecCSFlag for this
        // one, so we're doing it raw, which seems to work. not sure if I'd do this differently if I were
        // more familiar w/ Swift or MacOS internals.
        status = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue:kSecCSSigningInformation),
            &signingInfo
        )
        
        guard status == errSecSuccess, let signingInfo else {
            //SecCodeCopySigningInformation fails
            return SigningSummary(team: nil, id: nil, certificates: nil, entitlements: nil, runtime: nil,
                                  status: status, trustCategory: .unknown, appStorePolicyOIDEvidence: OIDEvidence.unknown(reason: "Signing information unavailable."),
                                  entitlementsEvidence: EntitlementsEvidence.unknown(reason: "Signing information unavailable"))
        }
        
        // info is our master srtucture w/ signing info from the OS here
        let info = signingInfo as NSDictionary
        
#if false
        
        if let tmp = info[kSecCodeInfoFlags] as? NSNumber {
            // turn it into an OptionSet
            let flags = SecCodeSignatureFlags(rawValue: tmp.uint32Value)
            print(flags.contains(SecCodeSignatureFlags.runtime))
        }
        
        
#endif
        // sort out hardened runtime
        let hardenedRuntime: Bool?
        
        // get hardened runtime status
        if let tmp = info[kSecCodeInfoFlags] as? NSNumber {
            let flags = SecCodeSignatureFlags(rawValue: tmp.uint32Value)
            hardenedRuntime = flags.contains(SecCodeSignatureFlags.runtime)
        } else { hardenedRuntime = nil }
        
        
        // sort out some easy ones
        let certificates = info[kSecCodeInfoCertificates as String] as? [SecCertificate]
        let identifier = info[kSecCodeInfoIdentifier as String] as? String
        let teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
        let entitlements = info[kSecCodeInfoEntitlementsDict] as? [String: Any]
        
        // Calculate the fundamental trust category (apple, app store, 3p dev not appstore, unknown)
        let (trustCategory, oidEvidence) = evaluateTrust(
            status: status,
            teamID: teamID,
            identifier: identifier,
            certificates: certificates,
            path: path)
        
        //sort out entitlements evidence
        let entitlementsEvidence: EntitlementsEvidence
        // entitlemetns can be in the standard dict or in the below weird alternate place in cases I don't
        // understand
        let entitlementsAlt = info[kSecCodeInfoEntitlements] as? NSData
        // present if if entitlements has at least 1 key or kSecCodeInfoEntitlements is not nil
        // else absent
        if entitlementsAlt != nil {
            entitlementsEvidence = EntitlementsEvidence.present
        } else {
            if let e = entitlements {
                entitlementsEvidence = e.isEmpty ? EntitlementsEvidence.absent :  EntitlementsEvidence.present
            } else {
                entitlementsEvidence = EntitlementsEvidence.absent
            }
        }
        
        
        return SigningSummary(team: teamID,
                              id: identifier,
                              certificates: certificates,
                              entitlements: entitlements,
                              runtime: hardenedRuntime,
                              status: status,
                              trustCategory: trustCategory,
                              appStorePolicyOIDEvidence: oidEvidence,
                              entitlementsEvidence: entitlementsEvidence)
        
    }
    
    // OID (Object Identifier) for the "Mac App Store" Certificate Policy.
    // Presence of this OID in the leaf certificate confirms App Store origin.
    private static let appStoreOID = "1.2.840.113635.100.6.1.9"
    private static let appleTeamID = "59GAB85EFG"
    
    // MARK: - Trust Evaluation Logic
    /// Static function that takes raw signing evidence and returns a final trust category.
    private func evaluateTrust(status: OSStatus, teamID: String?, identifier: String?, certificates: [SecCertificate]?, path: URL) -> (TrustCategory,OIDEvidence) {
        
        if status != 0 { return (.unknown, OIDEvidence.unknown(reason: "Signagure check failed"))}
        
        if let team = teamID {
            // there's a team string, is it an apple team string?
            if (team == "APPLE_PLATFORM") || (team == CodeSigningInspector.appleTeamID) {
                return (.apple, OIDEvidence.absent)
            } else {
                // there's a team string but it doesn't look like an Apple string
                // it's 3rd party and either app store or not app store. look at the certs
                // to distinguish
                guard let certs = certificates, !certs.isEmpty else {
                    return (.unknown,OIDEvidence.unknown(reason:"Certificate information was unavailable for inspection."))
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
            // No Team ID *usually* means ad-hoc / local build but some Apple components
            // may contain team id the way we expect. treat com.apple.* as Apple
            // if the executable is in an OS-owned location.
            if let id = identifier, id.hasPrefix("com.apple") {
                let p = path.path
                let isSystemLocation =
                    p.hasPrefix("/System/") ||
                    p.hasPrefix("/usr/") ||
                    p.hasPrefix("/bin/") ||
                    p.hasPrefix("/sbin/")

                if isSystemLocation {
                    return (.apple, OIDEvidence.absent)
                }
            }

            // Otherwise: "valid signature but no publisher identity we can establish" bucket.
            return (.unsigned, OIDEvidence.absent)
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

