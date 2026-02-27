//
//  ProcessInspectorRecords.swift
//  ProcessTrustInspector
//
//  Raw record types produced by ProcessInspector before engine-level merge.
//

import Foundation
import AppKit
import Darwin

/// Low-level process information gathered via libproc / proc_pidinfo.
/// This represents structural OS-level facts about a process.
/// Used with NSWorkspaceRecord to stitch together ProcessSnapshot.
struct BSDRecord {
    let pid: pid_t
    let uid: uid_t?
    let parentPid: pid_t?

    /// Process start time derived from pbi_start_tvsec / pbi_start_tvusec.
    let startTime: Date?

    /// Path returned from proc_pidpath (if available).
    let pidPath: URL?

    /// Short command name (e.g. pbi_comm).
    let shortName: String?

    /// Longer name field if you choose to collect it (e.g. pbi_name).
    let longName: String?

    // by definition this is coming from BSD visibility.
    let visibility: Visibility = [.procPidVis]
}

/// Higher-level application metadata gathered via NSWorkspace / LaunchServices.
/// This represents user-facing app context rather than structural OS state.
/// Used with BSDRecord to stitch together ProcessSnapshot.
struct NSWorkspaceRecord {
    let pid: pid_t

    /// Bundle identifier if available.
    let bundleIdentifier: String?

    /// Executable URL from NSRunningApplication.
    let executableURL: URL?

    /// Localized display name from NSRunningApplication.
    let localizedName: String?

    /// Application icon (if available).
    let icon: NSImage?

    /// Launch date reported by NSRunningApplication.
    let startTime: Date?

    // by definition this is coming from NSWorkspace visibility.
    let visibility: Visibility = [.nsWorkspaceVis]
}
