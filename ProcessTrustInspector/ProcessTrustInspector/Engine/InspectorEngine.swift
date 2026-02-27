//
//  InspectorEngine.swift
//  ProcessTrustInspector
//
//  Orchestration + UI-facing state.
//
//  This file defines `InspectorEngine`, the layer that Views interact with.
//  It owns selection state, drives refresh, and turns raw inspection records
//  into the final `ProcessSnapshot` array the UI displays.
//
//  Responsibilities:
//  - Maintain UI state: process list, selection, refresh metadata.
//  - Orchestrate data collection via `ProcessInspector`.
//  - Merge BSD/libproc and NSWorkspace records into unified snapshots.
//  - Compute derived fields (visibility, bundle status, signing summary,
//    quarantine metadata).
//  - Build the narrative for the selected process.
//
//  Non-responsibilities:
//  - No kernel enumeration logic (handled by `ProcessInspector`).
//  - No low-level code signing parsing (handled by `CodeSigningInspector`).
//  - No risk scoring or security verdicts.
//
//  Notes:
//  - Everything is best-effort and point-in-time. Processes may exit during refresh.
//  - Missing data is normal and should not be treated as suspicious.
//

import Foundation
import Observation
import AppKit
import Darwin
import UniformTypeIdentifiers

/// UI-facing coordinator that merges raw inspection data into the models
/// the Views render.
///
/// `InspectorEngine` sits above the inspectors:
/// - `ProcessInspector` provides layer-specific records (BSD + NSWorkspace).
/// - The engine coalesces those records into final `ProcessSnapshot` objects.
/// - The engine performs light enrichment (signing, quarantine, visibility).
/// - The engine owns selection state and narrative output.
@Observable
final class InspectorEngine {

    // MARK: - Published engine state (observed by Views)

    /// Point-in-time array of running GUI applications.
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

    /// Rebuilds the full process list from scratch.
    ///
    /// We pull two views of the world:
    /// - BSD/libproc (the full PID universe)
    /// - NSWorkspace (application-layer processes)
    ///
    /// BSD is treated as the master set of PIDs. For each PID, we merge in
    /// richer app-level metadata when available (name, bundle ID, icon),
    /// then compute derived signals (visibility, signing, bundle status,
    /// quarantine, etc.) to construct a complete `ProcessSnapshot`.
    ///
    /// Finally, we apply the current scope (Apps vs All) and publish the
    /// resulting array to the UI.
    func refresh() {
        self.refreshCount += 1
        self.processes = []
        self.lastRefreshTime = Date()
        
        // this represents the fully merged and enriched list of ProcessSnapshots we
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
        
        // look for any processes in the nsWorkspacedict that haven't been added to masterFinalPidDict and include them
        // functionally this currently means any processes that were in ns but not in bsd
        // should only happen in very unlikely race situations (i think)
        
        for (pid, record) in nsWorkspacePidDict {
            
            if masterFinalPidDict[pid] == nil {

                let snapPid: pid_t = record.pid
                let snapStartTime: Date? = record.startTime
                let snapExecutablePath: URL? = record.executableURL
                let snapName: String? = record.localizedName
                let snapBundleIdentifier: String? = record.bundleIdentifier
                let snapIcon: NSImage? = record.icon
                let snapVisibility: Visibility = [.nsWorkspaceVis]
                
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
                                               uid: nil,
                                               parentPid: nil,
                                               parentPidName: nil,
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
            } // if bsdPidDict[pid] == nil
                
        } // iterating nsWorkspacePidDict for stragglers
        
        
        // if the current selected PID isn't in the newly regenerated process list (ie it has exited), clear
        if let selectedPID = self.selectedPID {
            if masterFinalPidDict[selectedPID] == nil {
                self.clearSelection()
            }
        }
        
        let allSnapshots = Array(masterFinalPidDict.values)

        if showAllProcesses {
            self.processes = allSnapshots
        } else {
            self.processes = allSnapshots.filter { $0.visibility.contains(.nsWorkspaceVis) }
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
        var err: Int32
        
        // pass 1 for size and errors
        let size: Int = pathstr.withCString { cpath in
            getxattr(cpath, "com.apple.quarantine", nil, 0, 0, 0)
        }

        if size == -1 {
            err = errno
            if err == ENOATTR { return .absent }
            else { return .unknown(reason: "getxattr failed (errno \(err))") }
        }
        
        // pass 2 for the struct
        var data = Data(count: size)
        var size2: Int = 0
        
        pathstr.withCString { cpath in
            data.withUnsafeMutableBytes { buffer in
            size2 = getxattr(cpath, "com.apple.quarantine", buffer.baseAddress, size, 0, 0)
            }
        }
        
        if size2 == -1 {
            err = errno
            return .unknown(reason: "getxattr failed (errno \(err))")
        }
        
        let slice = data.prefix(size2)
        let qDetailsStr = String(data: slice, encoding: .utf8)
        
        guard let qDetailsStr else {
            return .present(details: QuarantineDetails(
                    raw: "<non-utf8>",
                    flags: nil,
                    timestamp: nil,
                    agentName: nil,
                    eventIdentifier: nil))
        }
        
        let qDetailsStruct = parseQuarantineXattr(qDetailsStr)
        return .present(details:qDetailsStruct)

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
