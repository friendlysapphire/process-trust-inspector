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
                return (nil, "Signing information unavailable.")
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
                return (nil, "Signing information unavailable.")
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

        // MARK: - Title
        let title = snapshot.name ?? "Process Details"

        // MARK: - Trust Classification (orientation)
        let trust = TrustClassificationBlock(
            label: snapshot.trustLevel.displayName,
            evidence: [
                FactLine(
                    label: "Signature check",
                    value: signatureStatusString(from: snapshot.signingSummary),
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable (missing executable path or inspection failure)."
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
                        ? "Signing information unavailable."
                        : "No Team ID present in signature metadata."
                ),
                FactLine(
                    label: "Identifier",
                    value: snapshot.signingSummary?.identifier,
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable."
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
                    label: "Parent PID",
                    value: snapshot.parentPid.map { String($0) },
                    unknownReason: snapshot.parentPid == nil
                        ? "Parent PID unavailable (race condition or not visible in current scope)."
                        : nil
                ),

                FactLine(
                    label: "Parent process",
                    value: snapshot.parentPidName,
                    unknownReason: snapshot.parentPidName == nil
                        ? "Parent process name not visible via NSWorkspace."
                        : nil
                ),FactLine(
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

                FactLine(
                    label: "Start time",
                    value: formatStartTime(snapshot.startTime),
                    unknownReason: snapshot.startTime == nil
                        ? "Launch time unavailable."
                        : nil
                )
            ],
            interpretation: [
                "This section describes an identity snapshot of the selected running instance."
            ],
            limits: [
                LimitNote(text: "PIDs are ephemeral; refresh may invalidate this snapshot."),
                LimitNote(text: "Missing fields are normal and may reflect metadata absence, scope limits, or race conditions.")
            ]
        )

        // MARK: - Code Signing Section
        let signing = NarrativeSection(
            title: "Code Signing",
            facts: [
                FactLine(
                    label: "Signature status",
                    value: signatureStatusString(from: snapshot.signingSummary),
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing inspection unavailable (missing executable path or inspection failure)."
                        : nil
                ),
                FactLine(
                    label: "Team ID",
                    value: snapshot.signingSummary?.teamID,
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable."
                        : "No Team ID present in signature metadata."
                ),
                FactLine(
                    label: "Identifier",
                    value: snapshot.signingSummary?.identifier,
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable."
                        : "No signing identifier present."
                ),
                FactLine(
                    label: "Trust category",
                    value: snapshot.signingSummary?.trustCategory.displayName,
                    unknownReason: snapshot.signingSummary == nil
                        ? "Signing information unavailable."
                        : nil
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
                "Code signing provides a stable identity for the executable and supports integrity checks."
            ],
            limits: [
                LimitNote(text: "A valid signature does not imply safety or benign behavior."),
                LimitNote(text: "This describes the on-disk executable, not runtime memory state."),
                LimitNote(text: "Entitlements describe declared capabilities in the code signature; they do not indicate whether permissions were granted.")
            ]
        )
        
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
                }()
            ],
            interpretation: [
                "Quarantine metadata is an origin marker that can cause Gatekeeper checks when software crosses a trust boundary (for example, downloaded from the internet)."
            ],
            limits: [
                LimitNote(text: "Quarantine metadata can be removed or may be absent even for downloaded software."),
                LimitNote(text: "Presence indicates how the file arrived, not whether it is safe.")
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
                LimitNote(text: "Sandbox status is derived from declared entitlements in the code signature."),
                LimitNote(text: "Hardened Runtime is derived from code signing flags."),
                LimitNote(text: "These settings describe enforcement modes, not observed runtime behavior.")
            ]
        )

        // MARK: - Global Limits & Uncertainty
        let globalLimits: [LimitNote] = [
            LimitNote(text: "Scope: this tool enumerates user-space GUI applications via NSWorkspace."),
            LimitNote(text: "This is a point-in-time snapshot; processes may exit or change between refreshes."),
            LimitNote(text: "Unknown fields are expected and should be interpreted as 'unavailable', not 'suspicious'.")
        ]

        // MARK: - Return
        return EngineNarrative(
            title: title,
            trustClassification: trust,
            sections: [identity, signing, provenance, runtimeConstraints],
            globalLimits: globalLimits
        )
    }
}
