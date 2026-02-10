//
//  ProcessInspector.swift
//  ProcessTrustInspector
//
//  Core process inspection and identity aggregation.
//
//  This file defines ProcessInspector, a low-level inspector responsible for
//  producing point-in-time identity snapshots of running processes.
//
//  Responsibilities:
//  - Enumerate running applications via NSWorkspace.
//  - Resolve executable paths and bundle context.
//  - Retrieve BSD-level process metadata (UID, parent PID) via libproc.
//  - Query code-signing identity and entitlements via CodeSigningInspector.
//  - Detect quarantine metadata on executable files.
//
//  Non-responsibilities:
//  - No UI concerns.
//  - No state management or caching.
//  - No interpretation or trust narratives (handled elsewhere).
//
//  Notes:
//  - All OS queries are inherently racy: processes may exit or PIDs may be
//    recycled between inspection steps.
//  - This inspector intentionally operates on best-effort signals and may
//    return partial data when system metadata is unavailable.
//
//  Created by Aaron Weiss on 2/1/26.
//
import Foundation
import Observation
import AppKit
import Darwin


// TODO: consider removing NSWorkspace level calls and moving all to BSD level
// TODO: Migration to libproc (proc_name/proc_pidpath) will
// TODO: remove the dependency on NSWorkspace, allowing us to
// TODO: inspect background daemons and non-GUI processes.

/// Low-level inspector responsible for producing point-in-time identity
/// snapshots of running processes.
///
/// This type aggregates information from multiple system layers:
/// - Application-level metadata via NSWorkspace.
/// - BSD/kernel-level process metadata via libproc.
/// - Static code-signing identity via CodeSigningInspector.
/// - Filesystem provenance signals such as quarantine metadata.
///
/// All data returned is best-effort and reflects a moment-in-time view.
/// Processes may exit, change state, or have their PIDs recycled during inspection.
final class ProcessInspector {
    
    /// Helper responsible for extracting static code-signing identity
    /// and related security metadata from executable files.
    private let signingInspector = CodeSigningInspector()
    
    /// Produces a point-in-time identity snapshot for a running process.
    ///
    /// This method aggregates data from multiple system layers:
    /// 1. Application metadata (NSWorkspace)
    /// 2. BSD process metadata (libproc)
    /// 3. Static code-signing identity (CodeSigningInspector)
    /// 4. Filesystem provenance signals (quarantine metadata)
    ///
    /// - Parameter pid: The process identifier to inspect.
    /// - Returns: A populated `ProcessSnapshot` if the process is accessible,
    ///            or `nil` if the process exits or becomes unavailable during inspection.
    func getProcessSnapshot(from pid: pid_t) -> ProcessSnapshot? {
        
        // TODO: (identity): Migrate from pid_t to audit_token_t to ensure we aren't inspecting a recycled PID
        
        let appList = NSWorkspace.shared.runningApplications
        
        // find app by PID in appList
        guard let targetApp = appList.first(where: { $0.processIdentifier == pid }) else {
            // Normal race condition: process exited or list changed
            // between enumeration and selection.
            return nil
        }
    
        // marshal a bunch more data for the ProcessSnapShot we're going to construct and return
        let path = targetApp.executableURL
        
 
        //   bundled if the executable path is inside *.app/Contents/MacOS/
        // Bare otherwise
        
        
        let signingInfo: SigningSummary?
        let bundledStatus: BundledStatus
        let quarantineStatus: QuarantineStatus
        
        if let path {
            
            bundledStatus = path.absoluteString.contains(".app/Contents/MacOS/") ? BundledStatus.bundled : BundledStatus.bare
            
            signingInfo = self.signingInspector.getSigningSummary(path: path)
            
            quarantineStatus = getQuarantineStatus(for: path)
            
        } else {
            
            quarantineStatus = .unknown(reason: "Could not determine executableURL (path) to determine quarantine status")
            signingInfo = nil
            bundledStatus = .unknown(reason: "Could not determine executableURL (path) to determine bundle status")
            
        }
        
       // get the running user ID and parent PID from proc_pidinfo in the bowels of the os
        
        //int proc_pidinfo(int pid, int flavor, uint64_t arg, void *buffer, int buffersize)
        var parentPid: pid_t? = nil
        var processUid: pid_t = 0
        var parentApp: NSRunningApplication? = nil
        var parentAppName: String? = nil
        
        // zero initialize and sizeof() the struct we're sending into C land
        var bsdinfo = proc_bsdinfo()
        let bsdinfo_size = MemoryLayout<proc_bsdinfo>.size
        var got_ppid: Int32 = 0
        
        // We use proc_pidinfo with the PROC_PIDTBSDINFO flavor to get
        // the proc_bsdinfo struct, which contains the parent PID (pbi_ppid)
        // and the real user ID (pbi_uid)
        withUnsafeMutablePointer(to: &bsdinfo) { ptr in
            got_ppid = proc_pidinfo(Int32(pid),PROC_PIDTBSDINFO,0,ptr,Int32(bsdinfo_size))
            if got_ppid == bsdinfo_size {
                parentPid = pid_t(ptr.pointee.pbi_ppid)
                processUid = pid_t(ptr.pointee.pbi_uid)
            }
        }
        
        // if there's a parent PID, get the associated process name
        if let parentPid {
            parentApp = appList.first(where: { $0.processIdentifier == parentPid })
            if let parentApp {
                parentAppName = parentApp.localizedName
            }
        
        }
        
        
        return ProcessSnapshot(pid: pid,
                               uid: processUid,
                               parentPid: parentPid,
                               parentPidName: parentAppName,
                               name: targetApp.localizedName,
                               startTime: targetApp.launchDate,
                               bundleIdentifier: targetApp.bundleIdentifier,
                               executablePath: path,
                               signingSummary: signingInfo,
                               bundledStatus: bundledStatus,
                               quarantineStatus: quarantineStatus,
                               icon: targetApp.icon)
        
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
}
