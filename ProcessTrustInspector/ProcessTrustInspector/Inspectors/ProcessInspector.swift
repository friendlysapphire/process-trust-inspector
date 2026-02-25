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
    
   
    func getNSWorkspaceSnapshots() -> [pid_t : NSWorkspaceRecord] {
        
        var retNSWorkspaceRecords: [pid_t: NSWorkspaceRecord] = [:]
        
        let appList = NSWorkspace.shared.runningApplications
        
        for app in appList {
            
            let nsRecord = NSWorkspaceRecord(pid: app.processIdentifier,
                                             bundleIdentifier: app.bundleIdentifier,
                                             executableURL: app.executableURL,
                                             localizedName: app.localizedName,
                                             icon: app.icon,
                                             startTime: app.launchDate)
            
            retNSWorkspaceRecords[app.processIdentifier] = nsRecord
        }
        return retNSWorkspaceRecords
    }
    
    
    func getBSDSnapshots() -> [pid_t: BSDRecord] {
        
        var retBSDSnapshots: [pid_t: BSDRecord] = [:]
        
        let masterPIDArray = getMasterBSDPidArray()
        
        //print("master pid array has size \(masterPIDArray.count)")
        
        for pid in masterPIDArray {
            
            var parentPid: pid_t?
            var processUid: uid_t?
            var bsdPath: URL?
            var bsdStartTime: Date?
            var bsdLongName: String?
            var bsdShortName: String?
            
            var status: Int32
            var bsdPidInfo = proc_bsdinfo()
            let bsdPidInfoSize = Int32(MemoryLayout<proc_bsdinfo>.size)
            
            // try to get the bsdinfo struct for this pid
            // returns bytes returned or -1 on erroe
            status = proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &bsdPidInfo, bsdPidInfoSize)
            
            if status >= bsdPidInfoSize {
                parentPid = pid_t(bsdPidInfo.pbi_ppid)
                processUid = bsdPidInfo.pbi_uid
                bsdLongName = decodeFixedCString(bsdPidInfo.pbi_comm)
                bsdShortName = decodeFixedCString(bsdPidInfo.pbi_name)
                
                // sometimes tme info is weird, so only proceed if it's sane
                if bsdPidInfo.pbi_start_tvsec > 0 {
                    
                    let seconds = Double(bsdPidInfo.pbi_start_tvsec)
                    let microseconds = Double(bsdPidInfo.pbi_start_tvusec) / 1_000_000.0
                    let timestamp = seconds + microseconds
                    
                    bsdStartTime = Date(timeIntervalSince1970: timestamp)
                }
            } else {
                // do something on error getting bsdinfo?
            }
            
            // now get the bsdPath
            var pathBuffer = [CChar](repeating: 0, count: Int(PATH_MAX))
            let result = proc_pidpath(pid, &pathBuffer, UInt32(PATH_MAX))
            if result > 0 {
                if let bsdPathAsStr = decodeCStringBuffer(pathBuffer) {
                    bsdPath = URL(fileURLWithPath: bsdPathAsStr)
                }
            }
            
            let bsdNnap = BSDRecord(pid: pid,
                                    uid: processUid,
                                    parentPid: parentPid,
                                    startTime: bsdStartTime,
                                    pidPath: bsdPath,
                                    shortName: bsdShortName,
                                    longName: bsdLongName)
            
            retBSDSnapshots[pid] = bsdNnap
        }
        
        return retBSDSnapshots
    }
    
    /// Calls into the OS for an array of PIDs representing all running processes
    /// (that the OS is willing to tell us about at least)
    /// returns [pid_t] of that list with 0 pid entries filtered out.
    private func getMasterBSDPidArray() -> [pid_t] {
        
        let pid_tSize = Int32(MemoryLayout<pid_t>.size)
          
        // first call to proc_listpids, get the num bytes returned so we can call again
        // with an allocated buffer
        var numBytes = proc_listpids(UInt32(PROC_ALL_PIDS), 0, nil, 0)
          
        guard numBytes != 0 else {
            let currentErrno = errno
            let errorCString = strerror(currentErrno)
            if let errorString = String(validatingUTF8: errorCString!) {
                print("listpids failed: \(errorString) (errno: \(currentErrno))")
            }
            
            return []
          }
          
        // allocate a buffer to receive the pid list
        let numPids = numBytes / pid_tSize
        var pidArray = [pid_t](repeating: 0, count: Int(numPids))
          
        // second call into proc_listpids with the newly mallocd buffer, fills pidArray
        numBytes = proc_listpids(UInt32(PROC_ALL_PIDS), 0, &pidArray, numBytes)
        
        guard numBytes != 0 else {
            //print("LISTPID error: proc_listpids returned 0 bytes")
            return []
        }
          
          // remove pid 0s
         return pidArray.filter { pid in pid != 0 }
        
    }
    
    /// Decode a fixed-size C char array field (imported from C as a tuple)
    /// into a Swift `String`.
    ///
    /// Use this when reading string fields embedded in C structs,
    /// like `proc_bsdinfo.pbi_comm` or `pbi_name`.
    ///
    /// Unlike `decodeCStringBuffer`, this is for struct fields with
    /// a compile-time fixed size — not for `[CChar]` buffers
    /// allocated and passed into a C function.
    private func decodeFixedCString<T>(_ field: T) -> String? {
        // Make a mutable copy so we can take a stable address for withUnsafeBytes.
        var copy = field

        return withUnsafeBytes(of: &copy) { rawBuffer -> String? in
            // Treat it as bytes, find the first NUL terminator, then UTF-8 decode.
            guard let nulIndex = rawBuffer.firstIndex(of: 0) else {
                // No terminator found; treat as invalid/unknown rather than guessing.
                return nil
            }

            let bytes = rawBuffer.prefix(upTo: nulIndex)
            return String(decoding: bytes, as: UTF8.self)
        }
    }

    /// Decode a null-terminated C string stored in a mutable `[CChar]` buffer
    /// (e.g. filled by `proc_pidpath`) into a Swift `String`.
    ///
    /// Use this when you’ve called a C API that writes into a buffer you allocated
    /// and you need to convert that buffer to a Swift string.
    ///
    /// Unlike `decodeFixedCString`, this is for dynamic buffers like `[CChar]`,
    /// not fixed-size struct fields imported as tuples.
    private func decodeCStringBuffer(_ buffer: [CChar]) -> String? {
        guard let nullIndex = buffer.firstIndex(of: 0) else {
            return nil // no null terminator found
        }

        let slice = buffer[..<nullIndex]
        let bytes = slice.map { UInt8(bitPattern: $0) }

        return String(decoding: bytes, as: UTF8.self)
    }
    
}

