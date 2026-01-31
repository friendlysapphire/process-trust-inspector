//
//  RunningAppRow.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/31/26.
//

import Foundation

struct RunningAppRow: Identifiable {
    let id: pid_t
    let pPid: pid_t
    let pName: String?
    let pBundleIdentifier: String?
    
    init(pPid:pid_t = 0, pName:String?, pBI:String?) {
        self.pPid = pPid
        self.id = pPid
        self.pName = pName
        self.pBundleIdentifier = pBI
    }
}
