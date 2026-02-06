//
//  InspectorEngine.swift
//  ProcessTrustInspector
//
// High-level State Coordinator for the Process & Trust Inspector.
//
// Responsibilities:
// - Maintain the source-of-truth for the UI (Selected PID, Snapshot, Metadata)
// - Enumerate GUI applications (NSWorkspace) for the primary navigation list
// - Orchestrate data collection by delegating to specialized inspectors
//   (ProcessInspector, CodeSigningInspector)
// - Transform raw process data into a human-readable narrative
//
// Non-responsibilities:
// - No direct kernel/syscall logic (delegated to ProcessInspector)
// - No low-level code signing logic (delegated to CodeSigningInspector)
// - No security verdicts or risk assessments
//
// Design notes:
// - Acts as a "Controller" in the MVVM/Observable pattern
// - Failure-tolerant: If an inspection fails, the engine transitions to an
//   explanatory error state rather than crashing.


import Foundation
import Observation
import AppKit
import Darwin

@Observable
final class InspectorEngine {
    
    // MARK: - Published engine state (observed by Views)
    
    /// Point-in-time list of running GUI applications.
    /// Derived from NSWorkspace and refreshed manually.
    var processes: [ProcessSnapshot] = []
    
    /// Snapshot for the currently selected PID, if inspection succeeds.
    /// Nil when selection fails or data is unavailable.
    var selectedSnapshot: ProcessSnapshot? = nil
    
    /// Currently selected PID (best-effort handle; may become stale).
    var selectedPID: pid_t? = nil
    
    /// Diagnostic counters for UI/debug visibility.
    var runningAppCount: Int = 0
    var refreshCount: Int = 0
    
    // data structure for providing output to UI.
    // this represents the primary output product of the tool
    var selectedNarrative: EngineNarrative? = nil
    
    // MARK: - Inspectors
    
    /// Inspectors for looking into data structures
    private let processInspector = ProcessInspector()
    
    /// Coordinates the inspection of a specific process.=
    /// This method acts as the primary bridge between the user's selection
    /// and the low-level inspection subsystem.
    ///
    /// Workflow:
    /// 1. Updates the tracking PID for the UI.
    /// 2. Delegates data collection to the ProcessInspector.
    /// 3. Updates the 'narrative' (explanation text) based on the result.
    ///
    /// - Parameter pid: The process identifier to inspect.
    func select(pid: pid_t) {
        
        guard let snapshot = self.processes.first(where: { $0.pid == pid} ) else {
            self.clearSelection()
            return
        }
        // apparently if you use first() it will call the wrong first() .... wtf.
        self.selectedSnapshot = snapshot
        self.selectedPID = pid
        self.selectedNarrative = buildEngineNarrative(from: snapshot)
    }

    
    /// Clears out stored properties associated with previosuly selected process
    func clearSelection() {
        
        self.selectedPID = nil
        self.selectedSnapshot = nil
        self.selectedNarrative = nil
    }
    
    /// Refreshes the point-in-time list of running GUI applications.
    ///
    /// Scope limitation:
    /// - Uses NSWorkspace, so this only includes user-space GUI apps.
    /// - CLI tools and background processes are intentionally out of
    ///   scope at this stage.
    
    func refresh() {
        self.refreshCount += 1
        self.processes = []
        
        let appList = NSWorkspace.shared.runningApplications
        
        for app in appList {
            
            let newProcess = processInspector.getProcessSnapshot(from: app.processIdentifier)
            
            if let newProcess {
                self.processes.append(newProcess)
            }
        }
        // if the current selected PID isn't in the current process list (ie it has exited), clear
        if let selectedPID = self.selectedPID {
            if !self.processes.contains(where: { $0.pid == selectedPID }) {
                self.clearSelection()
            }
        }
        
        self.runningAppCount = self.processes.count
    }

    private func buildEngineNarrative(from snapshot: ProcessSnapshot) -> EngineNarrative {

        // MARK: - Helpers (local to keep scope tight)
        func formatStartTime(_ date: Date?) -> String? {
            guard let date else { return nil }
            // another option:
            // ISO8601DateFormatter().string(from: date)
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
                ),

                FactLine(
                    label: "Bundle identifier",
                    value: snapshot.bundleIdentifier,
                    unknownReason: snapshot.bundleIdentifier == nil
                        ? "Not a bundled application or metadata unavailable."
                        : nil
                ),

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
                )
            ],
            interpretation: [
                "Code signing provides a stable identity for the executable and supports integrity checks."
            ],
            limits: [
                LimitNote(text: "A valid signature does not imply safety or benign behavior."),
                LimitNote(text: "This describes the on-disk executable, not runtime memory state.")
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
                }()
            ],
            interpretation: [
                "The App Sandbox is an opt-in containment model that restricts what an app can access by default."
            ],
            limits: [
                LimitNote(text: "Sandbox status is derived from declared entitlements in the app’s code signature."),
                LimitNote(text: "This does not describe all runtime behavior or guarantee isolation from other processes.")
            ]
        )


        // MARK: - Global Limits & Uncertainty (always visible)
        let globalLimits: [LimitNote] = [
            LimitNote(text: "Scope: this tool enumerates user-space GUI applications via NSWorkspace."),
            LimitNote(text: "This is a point-in-time snapshot; processes may exit or change between refreshes."),
            LimitNote(text: "Unknown fields are expected and should be interpreted as 'unavailable', not 'suspicious'.")
        ]

        // MARK: - Return
        return EngineNarrative(
            title: title,
            trustClassification: trust,
            sections: [identity, signing, runtimeConstraints],
            globalLimits: globalLimits
        )
    }

    init() {
        refresh()
    }
}
