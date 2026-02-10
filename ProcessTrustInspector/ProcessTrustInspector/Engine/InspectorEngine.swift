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

/// High-level state coordinator for the Process & Trust Inspector.
///
/// `InspectorEngine` is the UI-facing source of truth. It owns:
/// - The current process list (from `NSWorkspace`)
/// - The current selection (PID + snapshot)
/// - The current narrative output (the primary product shown in the detail view)
///
/// The engine does not perform low-level inspection itself. It orchestrates
/// specialized inspectors and transforms their output into stable, explanatory
/// models for the UI.
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
    var lastRefreshTime: Date? = nil
    
    // data structure for providing output to UI.
    // this represents the primary output product of the tool
    var selectedNarrative: EngineNarrative? = nil
    
    // MARK: - Inspectors
    
    /// Inspectors for looking into data structures
    private let processInspector = ProcessInspector()
    
    // builds narrative structures for UI
    private let narrativeBuilder = NarrativeBuilder()
    
    /// Selects a process by PID and updates the UI-facing state for the detail pane.
    ///
    /// This is a best-effort selection: the PID may be stale if the process exits
    /// or the list changes between refresh and selection.
    ///
    /// - Parameter pid: The process identifier to select.
    func select(pid: pid_t) {
        
        guard let snapshot = self.processes.first(where: { $0.pid == pid} ) else {
            self.clearSelection()
            return
        }
        self.selectedSnapshot = snapshot
        self.selectedPID = pid
        self.selectedNarrative = narrativeBuilder.build(from: snapshot)
    }

    
    /// Clears the current selection and associated detail output.
    ///
    /// After calling this, the UI should return to the “Select a process to inspect” state.
    func clearSelection() {
        
        self.selectedPID = nil
        self.selectedSnapshot = nil
        self.selectedNarrative = nil
    }
    
    /// Refreshes the point-in-time list of running applications visible to `NSWorkspace`.
    ///
    /// This is intentionally scoped to what LaunchServices/NSWorkspace exposes (mostly GUI apps,
    /// agents, and helpers). It is not a complete view of all system processes.
    ///
    /// Refresh also updates diagnostic counters and clears the current selection
    /// if the selected PID is no longer present.
    func refresh() {
        self.refreshCount += 1
        self.processes = []
        self.lastRefreshTime = Date()
        
        let appList = NSWorkspace.shared.runningApplications
        
        for app in appList {
            
            let newProcess = processInspector.getProcessSnapshot(from: app.processIdentifier)
            
            if let newProcess {
                self.processes.append(newProcess)
            }
        }
        // if the current selected PID isn't in the newly regenerated process list (ie it has exited), clear
        if let selectedPID = self.selectedPID {
            if !self.processes.contains(where: { $0.pid == selectedPID }) {
                self.clearSelection()
            }
        }
        
        self.runningAppCount = self.processes.count
    }

    /// Creates the engine and performs an initial refresh to populate the process list.
    init() {
        refresh()
    }
}
