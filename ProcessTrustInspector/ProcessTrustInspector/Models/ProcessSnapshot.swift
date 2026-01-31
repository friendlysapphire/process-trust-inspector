//
//  ProcessSnapshot.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/31/26.
//

import Foundation
import Security


struct ProcessSnapshot {
    let pPid: pid_t
    let pName: String?
    let pBundleIdentifier: String?
    let pExecutablePath: URL?
    let pSigningSummary: SigningSummary?
    
    init(pPid:pid_t, pName:String?, pBI:String?, pPidPath:URL?, signing:SigningSummary?) {
        self.pPid = pPid
        self.pName = pName
        self.pBundleIdentifier = pBI
        self.pExecutablePath = pPidPath
        self.pSigningSummary = signing
        
        /*TODO: use proc_pidpath (libproc.h) to capture non-GUI apps. */
    }
    
}
