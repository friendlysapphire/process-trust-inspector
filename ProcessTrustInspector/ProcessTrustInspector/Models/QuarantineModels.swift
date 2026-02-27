//
//  QuarantineDetails.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 2/26/26.
//

import Foundation

/// Describes quarantine info derived from getxattr call
struct QuarantineDetails {
    /// Raw xattr string (e.g. "01c1;69a0ad62;Firefox;UUID")
    let raw: String

    /// Flags bitmask (parsed from hex, if valid)
    let flags: UInt16?

    /// Timestamp decoded from hex (if valid and plausible)
    let timestamp: Date?

    /// Name of quarantining agent (e.g. "Firefox")
    let agentName: String?

    /// Fourth field (often UUID-like token)
    let eventIdentifier: String?
}

extension QuarantineDetails {
    var summary: String {
        var parts: [String] = []
        if let agentName, !agentName.isEmpty { parts.append("Agent: \(agentName)") }
        if let timestamp {
            parts.append("When: \(timestamp.formatted(date: .abbreviated, time: .shortened))")
        }
        if let eventIdentifier, !eventIdentifier.isEmpty { parts.append("ID: \(eventIdentifier)") }
        return parts.isEmpty ? "Present" : parts.joined(separator: " · ")
    }
}

func parseQuarantineXattr(_ raw: String) -> QuarantineDetails {
    let components = raw.split(separator: ";", omittingEmptySubsequences: false)
        .map { String($0) }

    // We expect at least 4 fields, but don’t assume.
    let flagsField = components.indices.contains(0) ? components[0] : nil
    let timestampField = components.indices.contains(1) ? components[1] : nil
    let agentField = components.indices.contains(2) ? components[2] : nil
    let eventField = components.indices.contains(3) ? components[3] : nil

    // Parse flags (hex → UInt16)
    let flags: UInt16? = {
        guard let f = flagsField else { return nil }
        return UInt16(f, radix: 16)
    }()

    // Parse timestamp (hex → Int → Date)
    let timestamp: Date? = {
        guard let ts = timestampField,
              let seconds = UInt64(ts, radix: 16)
        else { return nil }

        // Interpret as Unix epoch seconds.
        let date = Date(timeIntervalSince1970: TimeInterval(seconds))

        // Basic sanity check: reject absurd dates (optional but wise)
        let lowerBound = Date(timeIntervalSince1970: 0) // 1970
        let upperBound = Date().addingTimeInterval(60 * 60 * 24 * 365) // 1 year in future

        guard date >= lowerBound && date <= upperBound else {
            return nil
        }

        return date
    }()

    return QuarantineDetails(
        raw: raw,
        flags: flags,
        timestamp: timestamp,
        agentName: agentField,
        eventIdentifier: eventField
    )
}
