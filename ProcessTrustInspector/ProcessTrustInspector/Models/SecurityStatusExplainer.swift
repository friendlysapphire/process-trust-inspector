//
//  SecurityStatusExplainer.swift
//  Process Trust Inspector
//
//  Purpose:
//  Provide stable, human-readable explanations for Security.framework OSStatus
//  error codes, with best-effort system fallback text.
//
//  Responsibilities:
//  - Map a small set of known OSStatus values to stable, user-facing phrasing
//  - Provide a best-effort system error message via SecCopyErrorMessageString
//  - Keep interpretation centralized so narrative/UI code stays simple
//
//  Non-responsibilities:
//  - Performing any code-signing inspection
//  - Deciding trust classification or meaning beyond “what failed”
//  - UI formatting or presentation decisions
//

import Foundation
import Security

struct OSStatusExplanation {
    let code: OSStatus

    /// Stable, product-owned phrasing.
    /// This should not change often, even if Apple changes system strings.
    let short: String

    /// Best-effort system message from Security.framework.
    /// This may be nil, and it may vary across OS versions/locales.
    let systemMessage: String?

    /// Optional name of a known constant (if mapped), for debugging and logs.
    let constantName: String?
}

enum SecurityStatusExplainer {

    /// Main entry point.
    static func explain(_ status: OSStatus) -> OSStatusExplanation {
        if status == errSecSuccess {
            return OSStatusExplanation(
                code: status,
                short: "Success",
                systemMessage: nil,
                constantName: "errSecSuccess"
            )
        }

        let sys = systemMessage(for: status)

        if let mapped = mappedShortText(for: status) {
            return OSStatusExplanation(
                code: status,
                short: mapped.short,
                systemMessage: sys,
                constantName: mapped.constantName
            )
        }

        return OSStatusExplanation(
            code: status,
            short: "Security framework error",
            systemMessage: sys,
            constantName: nil
        )
    }

    // MARK: - Known mappings (actually seen irl)
    
    private static func mappedShortText(for status: OSStatus) -> (short: String, constantName: String)? {
        switch status {

         case errSecCSUnsigned:
             return ("Unsigned or ad-hoc signed", "errSecCSUnsigned")

         case errSecCSSignatureFailed:
             return ("Signature validation failed", "errSecCSSignatureFailed")

         case errSecCSBadResource:
             return ("Bundle resources did not match the signature", "errSecCSBadResource")

         case errSecCSResourcesInvalid:
             return ("Bundle resources were invalid for signature validation", "errSecCSResourcesInvalid")

         case errSecIO:
             return ("File could not be read", "errSecIO")

         case errSecParam:
             return ("Invalid parameter passed to Security framework", "errSecParam")

        default:
            return nil
        }
    }

    // MARK: - System fallback

    private static func systemMessage(for status: OSStatus) -> String? {
        guard let cf = SecCopyErrorMessageString(status, nil) else { return nil }

        let s = (cf as String).trimmingCharacters(in: .whitespacesAndNewlines)
        return s.isEmpty ? nil : s
    }
}
