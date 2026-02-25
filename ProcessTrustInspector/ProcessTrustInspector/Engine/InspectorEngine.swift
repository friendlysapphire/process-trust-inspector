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
import UniformTypeIdentifiers

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
    /// TODO: not really material for this app, but this would perform better
    /// as a [pid_t : ProcessSnapshot] instead of an array.
    var processes: [ProcessSnapshot] = []
    
    /// Snapshot for the currently selected PID, if inspection succeeds.
    /// Nil when selection fails or data is unavailable.
    var selectedSnapshot: ProcessSnapshot? = nil
    
    /// Currently selected PID (best-effort handle; may become stale).
    var selectedPID: pid_t? = nil
    
    /// Diagnostic counters for UI/debug visibility.
    var runningProcessCount: Int = 0
    var refreshCount: Int = 0
    var lastRefreshTime: Date? = nil
    
    // data structure for providing output to UI.
    // this represents the primary output product of the tool
    var selectedNarrative: EngineNarrative? = nil
    
    /// Controls whether BSD-only processes (not visible via NSWorkspace)
    /// are included in the UI list.
    var showAllProcesses: Bool = false
    
    // MARK: - Inspectors
    
    /// Inspectors for looking into data structures
    private let processInspector = ProcessInspector()
    
    /// Helper responsible for extracting static code-signing identity
    /// and related security metadata from executable files.
    private let signingInspector = CodeSigningInspector()
    
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
        self.selectedNarrative = narrativeBuilder.build(from: snapshot,
                                                        getParentSnapshotInfo(childSnapshot: snapshot))
    }

    /// takes a process snapshot and returns ParentProcessInfo enum modeling
    /// info about its parent process
    func getParentSnapshotInfo(childSnapshot: ProcessSnapshot) -> ParentProcessInfo {
       
        // validate the snapshot contains a parent pid, if not all we know is it's unavailable for
        // some unspecified reason.
        guard let pPid = childSnapshot.parentPid else {
            return ParentProcessInfo.noParentPID(reason: "Parent PID unavailable (not provided by inspection source).")
        }
 
        guard let parentSnapshot = self.processes.first(where: { $0.pid == pPid} ) else {
            return ParentProcessInfo.parentNotVisible(pid: pPid, reason: "Parent process not visible.")
        }
       
        return ParentProcessInfo.parentAvailable(parent: parentSnapshot)
    }


    /// Clears the current selection and associated detail output.
    ///
    /// After calling this, the UI should return to the “Select a process to inspect” state.
    func clearSelection() {
        
        self.selectedPID = nil
        self.selectedSnapshot = nil
        self.selectedNarrative = nil
    }
    

    func refresh() {
        self.refreshCount += 1
        self.processes = []
        self.lastRefreshTime = Date()
        
        // this will represent the fully merged and enriched list of ProcessSnapshots we
        // will expose to the UI as self.processes array.
        var masterFinalPidDict: [pid_t : ProcessSnapshot] = [:]
        
        // for each element in the BSD dict, constuct a ProcessSnapshot and fill based on best values
        // set self.processes to Array(bsdpiddict.values)
        
        let bsdPidDict = processInspector.getBSDSnapshots()
        
       // print("received \(bsdPidDict.count) bsd processes")
        
        let nsWorkspacePidDict = processInspector.getNSWorkspaceSnapshots()
        
       // print("received \(nsWorkspacePidDict.count) nsworkspace processes")
        
        // use the pids in bsdPidDict as the master w/ nsworkspace as the overlay
        
        for (pid, record) in bsdPidDict {
            
            //from bsd record
            let snapPid: pid_t = record.pid
            let snapUid: uid_t? = record.uid
            let snapParentPid: pid_t? = record.parentPid
            
            // prefer bsd record
            let snapStartTime: Date? = record.startTime ?? nsWorkspacePidDict[pid]?.startTime
            let snapExecutablePath: URL? = record.pidPath ?? nsWorkspacePidDict[pid]?.executableURL
            
            // prefer nsworkspace record
            let snapName: String? = nsWorkspacePidDict[pid]?.localizedName ?? record.shortName
            
            // from nsworkspace record
            let snapBundleIdentifier: String? = nsWorkspacePidDict[pid]?.bundleIdentifier
            let snapIcon: NSImage? = nsWorkspacePidDict[pid]?.icon
            
            // reach in and get parentpids name
            
            var snapParentPidName: String?
            
            if let parentPid = record.parentPid {
                snapParentPidName = nsWorkspacePidDict[parentPid]?.localizedName ?? bsdPidDict[parentPid]?.shortName
            }
            
            // /merge
            
            // compute visibility
            var snapVisibility: Visibility = [.procPidVis]
            if nsWorkspacePidDict[pid] != nil {
                snapVisibility.insert(.nsWorkspaceVis)
            }
            
            // compute signingInfo, bundleStatus, QuarantineStatus
            let snapSigningInfo: SigningSummary?
            let snapBundledStatus: BundledStatus
            let snapQuarantineStatus: QuarantineStatus
            
            if let snapExecutablePath {
                
                snapBundledStatus = snapExecutablePath.path.contains(".app/Contents/MacOS/") ? BundledStatus.bundled : BundledStatus.bare
                
                snapSigningInfo = self.signingInspector.getSigningSummary(path: snapExecutablePath)
                snapQuarantineStatus = getQuarantineStatus(for: snapExecutablePath)
                
            } else {
                
                snapQuarantineStatus = .unknown(reason: "Could not determine process path to determine quarantine status")
                snapSigningInfo = nil
                snapBundledStatus = .unknown(reason: "Could not determine process path to determine bundle status")
                
            }
            
            let snapshot = ProcessSnapshot(pid: snapPid,
                                           uid: snapUid,
                                           parentPid: snapParentPid,
                                           parentPidName: snapParentPidName,
                                           name: snapName,
                                           startTime: snapStartTime,
                                           bundleIdentifier: snapBundleIdentifier,
                                           executablePath: snapExecutablePath,
                                           signingSummary: snapSigningInfo,
                                           bundledStatus: snapBundledStatus,
                                           quarantineStatus: snapQuarantineStatus,
                                           icon: snapIcon,
                                           visibility: snapVisibility)
            
            masterFinalPidDict[pid] = snapshot
        }
        
        // TODO: look for any PIDs in nsworkspacepisdict but not in bsdpidict and create processsnapshots for them
        
        let allSnapshots = Array(masterFinalPidDict.values)

        if showAllProcesses {
            self.processes = allSnapshots
        } else {
            self.processes = allSnapshots.filter { $0.visibility.contains(.nsWorkspaceVis) }
        }
        
        // if the current selected PID isn't in the newly regenerated process list (ie it has exited), clear
        if let selectedPID = self.selectedPID {
            if !self.processes.contains(where: { $0.pid == selectedPID }) {
                self.clearSelection()
            }
        }
        
        self.runningProcessCount = self.processes.count
        //print("process struct contains \(self.runningProcessCount) processes")
    }

    /// Determines whether quarantine metadata is present on an executable file.
    ///
    /// This inspects the presence of the `com.apple.quarantine` extended attribute.
    /// Absence of this attribute does not imply local origin or safety; metadata
    /// may be missing, stripped, or never applied depending on the execution path.
    ///
    /// - Parameter url: The executable file URL to inspect.
    /// - Returns: A `QuarantineStatus` representing observed presence, absence,
    ///            or an unknown/error condition.
    private func getQuarantineStatus(for url: URL) -> QuarantineStatus {
        
        let pathstr = url.path
    
        let result = pathstr.withCString { cpath in
            getxattr(cpath, "com.apple.quarantine", nil, 0, 0, 0)
        }
        
        if result >= 0 { return .present }
        
        if errno == ENOATTR { return .absent }
        
        else { return .unknown(reason: "getxattr failed (errno \(errno))") }
    }
    
    func copySelectedReportToClipboard() {
        guard let narrative = selectedNarrative else { return }
        let text = narrative.asPlainText()
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
    
    @MainActor
    func exportSelectedReportAsMarkdown() {
        guard let narrative = selectedNarrative else { return }

        
        let panel = NSSavePanel()

        if let mdType = UTType(filenameExtension: "md") {
            panel.allowedContentTypes = [mdType]
        }

        panel.nameFieldStringValue = "process-report.md"
        panel.canCreateDirectories = true

        if panel.runModal() == .OK, let url = panel.url {
            do {
                try narrative.asMarkdown().write(to: url, atomically: true, encoding: .utf8)
            } catch {
                print("Failed to export markdown: \(error)")
            }
        }
    }
    
    /// Creates the engine and performs an initial refresh to populate the process list.
    init() {
        refresh()
    }
}
