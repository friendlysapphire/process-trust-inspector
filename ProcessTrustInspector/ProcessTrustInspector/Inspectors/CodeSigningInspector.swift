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
            
            return SigningSummary(team: nil, id: nil, certificates: nil, entitlements: nil, runtime: nil, status: status)
        }
        
        // get the signing info from that static code object
        var signingInfo: CFDictionary?
        status = SecCodeCopySigningInformation(
            staticCode,
            SecCSFlags(rawValue:kSecCSSigningInformation),          // default flags
            &signingInfo
        )
        
        guard status == errSecSuccess, let signingInfo else {
            return SigningSummary(team: nil, id: nil, certificates: nil, entitlements: nil, runtime: nil, status: status)
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
        
        
        
        return SigningSummary(team: teamID,
                              id: identifier,
                              certificates: certificates,
                              entitlements: entitlements,
                              runtime: hardenedRuntime,
                              status: status)
        
    }
    
}


