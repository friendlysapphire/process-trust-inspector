//
//  NarrativeBuilder.swift
//  ProcessTrustInspector
//
//  Builds the explanation-first narrative for a selected process.
//
//  This file intentionally contains no state management,
//  no inspection logic, and no UI concerns.
//  It is a pure transformation from ProcessSnapshot → EngineNarrative.
//

import Foundation

struct NarrativeBuilder {

    func build(from snapshot: ProcessSnapshot) -> EngineNarrative {

        // MARK: - Helpers (local to keep scope tight)
        func formatStartTime(_ date: Date?) -> String? {
            guard let date else { return nil }
            return date.formatted(date: .abbreviated, time: .standard)
        }

        func signatureStatusString(from summary: SigningSummary?) -> String? {
            guard let summary else { return nil }
            if summary.status == 0 {
                return "Valid"
            } else {
                return "Failed (OSStatus \(summary.status))"
            }
        }

        func appStoreOIDEvidenceDisplay(from summary: SigningSummary?) -> (value: String?, unknownReason: String?) {
            guard let summary else {
                return (nil, "Signing information unavailable (inspection limits).")
            }

            let evidence = summary.appStorePolicyOIDEvidence

            switch evidence {
            case .present(let oid):
                return ("Present (\(oid))", nil)
            case .absent:
                return ("Not present", nil)
            case .unknown(let reason):
                return (nil, reason)
            }
        }

        func appSandboxDisplay(from snapshot: ProcessSnapshot) -> (value: String?, unknownReason: String?) {
            switch snapshot.isSandboxed {
            case .sandboxed:
                return ("Yes", nil)
            case .notSandboxed:
                return ("No", nil)
            case .unknown(let reason):
                return (nil, reason)
            }
        }

        func hardenedRuntimeDisplay(from snapshot: ProcessSnapshot) -> (value: String?, unknownReason: String?) {
            switch snapshot.hasHardenedRuntime {
            case .hasHardenedRuntime:
                return ("Yes", nil)
            case .noHardenedRuntime:
                return ("No", nil)
            case .unknown(let reason):
                return (nil, reason)
            }
        }

        func entitlementsEvidenceDisplay(from summary: SigningSummary?) -> (value: String?, unknownReason: String?) {
            guard let summary else {
                return (nil, "Signing information unavailable (inspection limits).")
            }
            switch summary.entitlementsEvidence {
            case .present:
                return ("Present", nil)
            case .absent:
                return ("Not present", nil)
            case .unknown(let reason):
                return (nil, reason)
            }
        }

        func bundledStatusDisplay(from snapshot: ProcessSnapshot) -> (value: String?, unknownReason: String?) {
            switch snapshot.bundledStatus {
            case .bundled:
                return ("Yes", nil)
            case .bare:
                return ("No", nil)
            case .unknown(let reason):
                return (nil, reason)
            }
        }

        func quarantineStatusDisplay(from snapshot: ProcessSnapshot) -> (value: String?, unknownReason: String?) {
            switch snapshot.quarantineStatus {
            case .present:
                return ("Present", nil)
            case .absent:
                return ("Not present", nil)
            case .unknown(let reason):
                return (nil, reason)
            }
        }

        func gatekeeperRelevanceDisplay(from snapshot: ProcessSnapshot) -> (value: String?, unknownReason: String?) {

            // If quarantine is present, Gatekeeper relevance is straightforward.
            switch snapshot.quarantineStatus {
            case .present:
                return ("Gatekeeper evaluation likely (quarantine metadata present)", nil)
            case .unknown(let reason):
                return (nil, reason)
            case .absent:
                break
            }

            // If the file isn't quarantined, Gatekeeper may not have evaluated it.
            switch snapshot.bundledStatus {
            case .unknown(let reason):
                return (nil, reason)
            case .bare:
                return ("Gatekeeper evaluation unlikely (not an app bundle)", nil)
            case .bundled:
                return ("Gatekeeper evaluation possible (app bundle; no quarantine metadata observed)", nil)
            }
        }

        // MARK: - Narrative Summary (primary product)
        func buildSummary(from snapshot: ProcessSnapshot) -> [String] {
            var lines: [String] = []

            lines.append("Overview")

            if let name = snapshot.name, !name.isEmpty {
                if let bundleID = snapshot.bundleIdentifier, !bundleID.isEmpty {
                    lines.append("“\(name)” (\(bundleID))")
                } else {
                    lines.append("“\(name)”")
                }
            } else {
                lines.append("Selected process")
            }

            lines.append("Signing identity: \(snapshot.trustLevel.displayName)")

            if let summary = snapshot.signingSummary {
                lines.append(
                    summary.status == 0
                    ? "Code signature: Valid"
                    : "Code signature: Failed (OSStatus \(summary.status))"
                )
            } else {
                lines.append("Code signature: Unavailable")
            }

            // Unsigned / ad-hoc explainer (narrative-owned)
            if snapshot.trustLevel == .unsigned {
                lines.append(
                    "“No Publisher Identity” includes ad-hoc or locally built software. A code signature may be valid, but no publisher identity can be established."
                )
            }

            func iconObserved(value: String?, unknownReason: String?) -> String {
                if let r = unknownReason, !r.isEmpty { return "⚠️" }
                guard let v = value?.trimmingCharacters(in: .whitespacesAndNewlines), !v.isEmpty else { return "⚠️" }

                if v.caseInsensitiveCompare("Yes") == .orderedSame { return "✅" }
                if v.caseInsensitiveCompare("No") == .orderedSame { return "❌" }

                let lower = v.lowercased()
                if lower.contains("not present") { return "❌" }
                if lower == "present" || (lower.contains("present") && !lower.contains("not")) { return "✅" }

                return "⚠️"
            }

            func iconInferred(unknownReason: String?) -> String {
                if let r = unknownReason, !r.isEmpty { return "⚠️" }
                return "❓"
            }

            do {
                let sbox = appSandboxDisplay(from: snapshot)
                let hr = hardenedRuntimeDisplay(from: snapshot)

                lines.append("Runtime constraints")
                lines.append("\(iconObserved(value: sbox.value, unknownReason: sbox.unknownReason)) App Sandbox")
                lines.append("\(iconObserved(value: hr.value, unknownReason: hr.unknownReason)) Hardened Runtime")
            }

            do {
                let q = quarantineStatusDisplay(from: snapshot)
                let gk = gatekeeperRelevanceDisplay(from: snapshot)

                lines.append("Provenance")
                lines.append("\(iconObserved(value: q.value, unknownReason: q.unknownReason)) Quarantine metadata")

                if snapshot.trustLevel == .apple {
                    lines.append("❓ Gatekeeper checks (typically not applicable to system components)")
                } else {
                    lines.append("\(iconInferred(unknownReason: gk.unknownReason)) Gatekeeper checks")
                    if let note = gk.value, !note.isEmpty {
                        lines.append(note)
                    }
                }
            }
            return lines
        }

        // MARK: - Title
        let title = snapshot.name ?? "Process Details"

        // MARK: - Trust Classification
        let trust = TrustClassificationBlock(
            label: snapshot.trustLevel.displayName,
            evidence: [
                FactLine(
                    label: "Code signature",
                    value: signatureStatusString(from: snapshot.signingSummary),
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable (inspection limits)."
                        : nil
                )
            ],
            interpretation: [
                "This classification is based on static code-signing identity of the on-disk executable (when available)."
            ],
            limits: [
                LimitNote(text: "This is not a safety verdict and does not describe runtime behavior."),
                LimitNote(text: "If signature details are unavailable, classification may be incomplete.")
            ]
        )

        // MARK: - Provenance Section
        let provenance = NarrativeSection(
            title: "Provenance",
            facts: [
                {
                    let q = quarantineStatusDisplay(from: snapshot)
                    return FactLine(
                        label: "Quarantine metadata",
                        value: q.value,
                        unknownReason: q.unknownReason
                    )
                }(),
                {
                    let gk = gatekeeperRelevanceDisplay(from: snapshot)
                    return FactLine(
                        label: "Gatekeeper applicability",
                        value: gk.value,
                        unknownReason: gk.unknownReason
                    )
                }()
            ],
            interpretation: [
                "These signals describe provenance and when Gatekeeper checks are more likely to be relevant."
            ],
            limits: [
                LimitNote(text: "Quarantine metadata may be absent or removed; absence does not imply local origin or safety."),
                LimitNote(text: "Gatekeeper checks are inferred from context and metadata; this tool does not directly observe whether Gatekeeper ran."),
                LimitNote(text: "This does not perform a Gatekeeper assessment and does not determine notarization status.")
            ]
        )

        // MARK: - Return
        return EngineNarrative(
            title: title,
            trustClassification: trust,
            sections: [provenance],
            summary: buildSummary(from: snapshot),
            globalLimits: []
        )
    }
}
