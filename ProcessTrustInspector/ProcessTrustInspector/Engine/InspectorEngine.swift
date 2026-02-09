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
    var lastRefreshTime: Date? = nil
    
    // data structure for providing output to UI.
    // this represents the primary output product of the tool
    var selectedNarrative: EngineNarrative? = nil
    
    // MARK: - Inspectors
    
    /// Inspectors for looking into data structures
    private let processInspector = ProcessInspector()
    
    // builds narrative structures for UI
    private let narrativeBuilder = NarrativeBuilder()
    
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
        self.selectedSnapshot = snapshot
        self.selectedPID = pid
        self.selectedNarrative = narrativeBuilder.build(from: snapshot)
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

    init() {
        refresh()
    }
}
