//
//  ProcessInspector.swift
//  ProcessTrustInspector
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

/// Specialized inspector for retrieving low-level OS/kernel metadata.
///
/// Responsibilities:
/// - Interface with NSWorkspace for higher level process info
/// - Interface with libproc (Darwin) to extract BSD-level process info.
/// - Resolve file system paths for active PIDs.
/// - Bridge the gap between raw PIDs and the CodeSigningInspector.
///
/// Note: All OS calls are subject to race conditions.
/// A process may exit or its PID may be recycled between
/// the time we fetch its info and the time we check its signature.
final class ProcessInspector {
    
    
    private let signingInspector = CodeSigningInspector()
    
    /// Generates a point-in-time identity snapshot for a given PID.
    ///
    /// This method aggregates data from multiple system layers:
    /// 1. App-level metadata (via NSWorkspace)
    /// 2. Kernel-level BSD info (via libproc)
    /// 3. Security/Identity metadata (via CodeSigningInspector)
    ///
    /// - Parameter pid: The process ID to inspect.
    /// - Returns: A populated ProcessSnapshot if the process is accessible,
    ///            or nil if the process has exited or the system call fails.
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
                               quarantineStatus: quarantineStatus)
        
    }
    
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
