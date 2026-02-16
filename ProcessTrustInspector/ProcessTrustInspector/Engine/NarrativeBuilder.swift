//
//  NarrativeBuilder.swift
//  Process Trust Inspector
//
//  Purpose:
//  Builds the explanation-first narrative for a selected process.
//
//  Responsibilities:
//  - Transforms ProcessSnapshot data into human-readable narrative sections
//  - Separates observed facts from interpretation and limits
//  - Produces stable, versioned narrative output for v1
//
//  Non-Responsibilities:
//  - Performing inspection or system calls
//  - Managing UI state or presentation
//
//  Notes:
//  - All output is best-effort and may include unknown or unavailable fields
//  - This file encodes product intent as much as technical behavior
//

import Foundation

/// Pure narrative transformer that converts a `ProcessSnapshot` into an
/// explanation-first `EngineNarrative`.
///
/// `NarrativeBuilder` encodes v1 product intent:
/// - Separates observed facts from interpretation and limits
/// - Produces stable, human-readable section output for the UI
/// - Treats missing data as normal and reports uncertainty explicitly
///
/// This type performs no inspection or system calls. It only formats and
/// organizes already-collected snapshot data into a narrative structure.
struct NarrativeBuilder {

    /// Builds the complete narrative representation for a single process snapshot.
    ///
    /// This method:
    /// - Constructs the top-level trust classification block
    /// - Builds sectioned facts, interpretation, and limits (Identity, Code Signing, etc.)
    /// - Generates the summary lines used in the detail view
    ///
    /// All output is best-effort and may contain unknown fields with explicit
    /// reasons when metadata is unavailable.
    ///
    /// - Parameter snapshot: A point-in-time process identity snapshot produced by the engine/inspectors.
    /// - Returns: A structured `EngineNarrative` that the UI can render without recomputing meaning.
    func build(from snapshot: ProcessSnapshot, _ parentInfo: ParentProcessInfo) -> EngineNarrative {

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
        
        func executableLocationDisplay(from snapshot: ProcessSnapshot) -> (value: String?, unknownReason: String?) {
            switch snapshot.executableLocationClass {
            case .systemOwned:
                return ("System-owned", nil)
            case .applications:
                return ("Applications", nil)
            case .userWritable:
                return ("User-writable", nil)
            case .externalVolume:
                return ("External volume", nil)
            case .temporary:
                return ("Temporary", nil)
            case .unknown(let reason):
                return (nil, reason)
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

            // Unsigned / ad-hoc explainer (short, calm, no "Note:" prefix)
            if snapshot.trustLevel == .unsigned {
                lines.append("“No Publisher Identity” includes ad-hoc or locally built software. A code signature may be valid, but no publisher identity can be established.")
            }

            // ✅ = observed present/yes
            // ❌ = observed absent/no
            // ❓ = inferred / conditional applicability (not directly observed)
            // ⚠️ = unknown / unavailable (inspection limits, missing metadata, race, etc.)

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

            // Runtime constraints (scannable)
            do {
                let sbox = appSandboxDisplay(from: snapshot)
                let hr = hardenedRuntimeDisplay(from: snapshot)

                lines.append("Runtime constraints")
                lines.append("\(iconObserved(value: sbox.value, unknownReason: sbox.unknownReason)) App Sandbox")
                lines.append("\(iconObserved(value: hr.value, unknownReason: hr.unknownReason)) Hardened Runtime")
            }

            // Provenance (observed + inferred)
            do {
                let q = quarantineStatusDisplay(from: snapshot)
                let gk = gatekeeperRelevanceDisplay(from: snapshot)

                lines.append("Provenance")
                lines.append("\(iconObserved(value: q.value, unknownReason: q.unknownReason)) Quarantine metadata")

                if snapshot.trustLevel == .apple {
                    lines.append("❓ Gatekeeper checks (typically not applicable to system components)")
                } else {
                    // Always two-line pattern: header line + smaller supporting line.
                    lines.append("\(iconInferred(unknownReason: gk.unknownReason)) Gatekeeper checks")
                    let eval = gk.value?.trimmingCharacters(in: .whitespacesAndNewlines)
                    if let eval, !eval.isEmpty {
                        lines.append(eval)
                    }
                }
            }

            return lines
        }

        // MARK: - Title
        let title = snapshot.name ?? "Process Details"

        // MARK: - Trust Classification (orientation)
        let trust = TrustClassificationBlock(
            label: snapshot.trustLevel.displayName,
            evidence: [
                FactLine(
                    label: "Code signature",
                    value: signatureStatusString(from: snapshot.signingSummary),
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable (inspection limits)."
                        : nil
                ),

                {
                    let oidDisplay = appStoreOIDEvidenceDisplay(from: snapshot.signingSummary)
                    return FactLine(
                        label: "App Store certificate policy OID",
                        value: oidDisplay.value,
                        unknownReason: oidDisplay.unknownReason
                    )
                }(),

                FactLine(
                    label: "Team ID",
                    value: snapshot.signingSummary?.teamID,
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable (inspection limits)."
                        : "No Team ID present in signature metadata."
                ),

                FactLine(
                    label: "Identifier",
                    value: snapshot.signingSummary?.identifier,
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable (inspection limits)."
                        : "No signing identifier present."
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

        // MARK: - Identity Section
        let identity = NarrativeSection(
            title: "Identity",
            facts: [
                FactLine(
                    label: "Process name",
                    value: snapshot.name,
                    unknownReason: snapshot.name == nil
                        ? "Process name unavailable."
                        : nil
                ),
                FactLine(label: "PID", value: "\(snapshot.pid)"),
                FactLine(label: "User ID", value: "\(snapshot.uid)"),
                FactLine(label: "Running as root", value: snapshot.runningAsRoot ? "Yes" : "No"),
                FactLine(
                    label: "Bundle identifier",
                    value: snapshot.bundleIdentifier,
                    unknownReason: snapshot.bundleIdentifier == nil
                        ? "No bundle identifier was available for this process."
                        : nil
                ),

                {
                    let b = bundledStatusDisplay(from: snapshot)
                    return FactLine(
                        label: "Bundled application",
                        value: b.value,
                        unknownReason: b.unknownReason
                    )
                }(),

                FactLine(
                    label: "Executable path",
                    value: snapshot.executablePath?.path,
                    unknownReason: snapshot.executablePath == nil
                        ? "Executable path unavailable from NSWorkspace."
                        : nil
                ),
                {
                    let loc = executableLocationDisplay(from: snapshot)
                    return FactLine(
                        label: "Executable location",
                        value: loc.value,
                        unknownReason: loc.unknownReason
                    )
                }(),

                FactLine(
                    label: "Start time",
                    value: formatStartTime(snapshot.startTime),
                    unknownReason: snapshot.startTime == nil
                        ? "Launch time unavailable."
                        : nil
                )
            ],
            interpretation: [
                "This section describes an identity snapshot of the selected running process.",
                "Executable location summarizes where the on-disk binary resides, which can help contextualize origin and control."
            ],
            limits: [
                LimitNote(text: "PIDs are ephemeral; refresh may invalidate this snapshot."),
                LimitNote(text: "Executable location is a filesystem hint; it does not prove who installed the software or how it arrived."),
                LimitNote(text: "Missing fields are normal and may reflect metadata absence, scope limits, or race conditions.")
            ]
        )
        // MARK: - Process Lineage
        let lineage: NarrativeSection = {
            func trustLabel(_ s: ProcessSnapshot) -> String {
                s.trustLevel.displayName
            }

            func yesNo(_ b: Bool) -> String { b ? "Yes" : "No" }

            let parentLine: FactLine
            var extraFacts: [FactLine] = []

            switch parentInfo {
            case .noParentPID(let reason):
                parentLine = FactLine(
                    label: "Parent process",
                    value: nil,
                    unknownReason: reason ?? "Parent PID not present in the process snapshot."
                )

            case .parentNotVisible(let pid, _):
                parentLine = FactLine(
                    label: "Parent process",
                    value: "PID \(pid) (not listed by NSWorkspace)",
                    unknownReason: nil
                )

            case .parentAvailable(let parent):
                let parentName = parent.name ?? "Unknown"
                parentLine = FactLine(
                    label: "Parent process",
                    value: "\(parentName) (PID \(parent.pid))",
                    unknownReason: nil
                )

                let parentTrust = trustLabel(parent)
                let childTrust = snapshot.trustLevel.displayName
                extraFacts.append(
                    FactLine(
                        label: "Trust category",
                        value: "\(parentTrust) -> \(childTrust)",
                        unknownReason: nil
                    )
                )

                extraFacts.append(
                    FactLine(
                        label: "Running as root",
                        value: "\(yesNo(parent.runningAsRoot)) -> \(yesNo(snapshot.runningAsRoot))",
                        unknownReason: nil
                    )
                )

                extraFacts.append(
                    FactLine(
                        label: "User ID",
                        value: "\(parent.uid) -> \(snapshot.uid)",
                        unknownReason: nil
                    )
                )

                // Single gentle indicator (not a warning system)
                var differences: [String] = []

                if parent.trustLevel != snapshot.trustLevel {
                    differences.append("Trust category differs")
                }

                if !parent.runningAsRoot && snapshot.runningAsRoot {
                    differences.append("Privilege increases (root child)")
                }

                if parent.uid != snapshot.uid {
                    differences.append("User ID differs")
                }

                if differences.isEmpty {
                    extraFacts.append(
                        FactLine(
                            label: "Relationship observation",
                            value: "No significant differences observed",
                            unknownReason: nil
                        )
                    )
                } else {
                    extraFacts.append(
                        FactLine(
                            label: "Relationship observation",
                            value: "Differences observed: " + differences.joined(separator: "; "),
                            unknownReason: nil
                        )
                    )
                }
            }

            var facts: [FactLine] = [parentLine]
            facts.append(contentsOf: extraFacts)

            return NarrativeSection(
                title: "Process Lineage",
                facts: facts,
                interpretation: [
                    "This section describes the parent process and relationship context",
                    "Selected characteristics are shown as parent → child for direct comparison."
                ],
                limits: [
                    LimitNote(text: "The parent may not appear in the NSWorkspace process list."),
                    LimitNote(text: "Parent relationships are point-in-time and may change between refreshes.")
                ]
            )
        }()
        // MARK: - Code Signing Section
        let signing = NarrativeSection(
            title: "Code Signing",
            facts: [
                FactLine(
                    label: "Trust category",
                    value: snapshot.signingSummary?.trustCategory.displayName,
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable (inspection limits)."
                        : nil
                ),
                FactLine(
                    label: "Signature status",
                    value: signatureStatusString(from: snapshot.signingSummary),
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable (inspection limits)."
                        : nil
                ),

                FactLine(
                    label: "Team ID",
                    value: snapshot.signingSummary?.teamID,
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable (inspection limits)."
                        : "No Team ID present in signature metadata."
                ),

                FactLine(
                    label: "Identifier",
                    value: snapshot.signingSummary?.identifier,
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable (inspection limits)."
                        : "No signing identifier present."
                ),

                {
                    let e = entitlementsEvidenceDisplay(from: snapshot.signingSummary)
                    return FactLine(
                        label: "Entitlements",
                        value: e.value,
                        unknownReason: e.unknownReason
                    )
                }()
            ],
            interpretation: [
                "Code signing provides a verifiable identity for the executable and supports integrity checks."
            ],
            limits: [
                LimitNote(text: "A valid signature does not imply safety or benign behavior."),
                LimitNote(text: "This describes the on-disk executable, not runtime memory state."),
                LimitNote(text: "Entitlements describe declared capabilities in the code signature; they do not indicate whether permissions were granted.")
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
                "These signals describe provenance and when Gatekeeper is more likely to evaluate an application at launch."
            ],
            limits: [
                LimitNote(text: "Quarantine metadata may be absent or removed; its absence does not imply that the software is safe."),
                LimitNote(text: "Gatekeeper behavior is inferred from context and metadata; this tool does not directly observe whether Gatekeeper evaluated the application."),
                LimitNote(text: "This tool does not perform a Gatekeeper assessment and does not determine notarization status.")
            ]
        )

        // MARK: - Runtime Constraints
        let runtimeConstraints = NarrativeSection(
            title: "Runtime Constraints",
            facts: [
                {
                    let sbox = appSandboxDisplay(from: snapshot)
                    return FactLine(
                        label: "App Sandbox",
                        value: sbox.value,
                        unknownReason: sbox.unknownReason
                    )
                }(),

                {
                    let rt = hardenedRuntimeDisplay(from: snapshot)
                    return FactLine(
                        label: "Hardened Runtime",
                        value: rt.value,
                        unknownReason: rt.unknownReason
                    )
                }()
            ],
            interpretation: [
                "These signals describe declared runtime enforcement modes for the selected executable."
            ],
            limits: [
                LimitNote(text: "Sandbox status is inferred from declared entitlements in the code signature."),
                LimitNote(text: "Hardened Runtime is inferred from code signing flags."),
                LimitNote(text: "These settings describe enforcement modes applied by the operating system at runtime; they do not describe observed runtime behavior.")
            ]
        )

        // MARK: - Global Limits & Uncertainty
        let globalLimits: [LimitNote] = [
            LimitNote(text: "Scope: This tool enumerates running applications visible to NSWorkspace (via LaunchServices). This includes user applications, background agents, and some helper processes, but does not represent a complete view of all running system processes."),
            LimitNote(text: "This is a point-in-time snapshot; processes may exit or change between refreshes."),
            LimitNote(text: "Unknown fields are expected and should be interpreted as unavailable, not suspicious.")
        ]

        // MARK: - Return
        return EngineNarrative(
            title: title,
            trustClassification: trust,
            sections: [identity, lineage, signing, provenance, runtimeConstraints],
            summary: buildSummary(from: snapshot),
            globalLimits: globalLimits
        )
    }
}
