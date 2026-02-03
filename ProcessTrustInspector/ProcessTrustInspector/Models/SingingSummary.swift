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
//  of the executable file and does NOT prove runtime behavior.

import Foundation
import Security

/// Models the 4 foundational code signature types
enum TrustCategory {
    case apple      // Signed by Apple (OS Component)
    case appStore   // Signed by Apple (App Store Distribution)
    case developer  // Signed by Developer ID (Direct Distribution)
    case unsigned   // Ad-hoc or Broken Signature
    
    var displayName: String {
        switch self {
        case .apple:
            return String("Apple Software")
        case .appStore:
            return String("App Store Software")
        case .developer:
            return String("Developer (Non-App Store) Software")
        case .unsigned:
            return String("Unsigned / Untrusted")
        }
    }
}

struct SigningSummary {
    let teamID: String?
    let identifier: String?
    let certificates: [SecCertificate]?
    let status: OSStatus
    
    private let appStoreOID = "1.2.840.113635.100.6.1.9"
    
    init(team: String?, id: String?, certificates: [SecCertificate]?, status: OSStatus) {
        self.teamID = team
        self.identifier = id
        self.status = status
        self.certificates = certificates
    }
    
    var trustCategory: TrustCategory {
        
        if self.status != 0 { return .unsigned }
        
        if let team = self.teamID {
            // there's a team string, is it an apple team string?
            if (team == "APPLE_PLATFORM") || (team == "59GAB85EFG") {
                return .apple
            } else {
                // there's a team string but it doesn't look like an Apple string
                // it's 3rd party and either app store or not app store. look at the certs
                // to distinguish
                guard let certs = self.certificates else {
                    return .unsigned
                }
                // grab the leaf node cert
                let certInfo = SecCertificateCopyValues(certs[0],nil,nil)
                
                if let cd = certInfo as? [String: Any] {
                    // extract the relevant cert string
                    let certString = getCertString(certDict: cd)
                    
                    if let certString, certString == appStoreOID {
                        // if we didn't get valid cert data back OR we did
                        // but it wasn't the appStoreOid, call it .developer
                        // (we still know it's signed w/o no error and has a team)
                        return .appStore
                    }
                }
                // fall through. we know we have a valid sig and team but couldn't find
                // app store origin evidence.
                return .developer
            }
        } else {
            // there's no team string, so it's either ad hoc (eg local dev, considered 'unsigned') or appl
            if let id = self.identifier, id.hasPrefix("com.apple") {
                return .apple
            } else { return .unsigned }
        }
    }
    
    // TODO: deal with the gross dict and return the right thing
    private func getCertString(certDict:[String: Any]) -> String? {
        return appStoreOID
    }

}
