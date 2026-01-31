//
//  SigningSummary.swift
//  ProcessTrustInspector
//  Created by Aaron Weiss on 1/31/26.
//
//
//  Represents a best-effort summary of static code-signing
//  identity for an on-disk executable.
//
//  This data is derived from Security.framework inspection
//  of the executable file and does NOT prove runtime behavior.

import Foundation
import Security

struct SigningSummary {
    let teamID: String?
    let identifier: String?
    let status: OSStatus

    init(team: String?, id: String?, status: OSStatus) {
        self.teamID = team
        self.identifier = id
        self.status = status
    }
}
