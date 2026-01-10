//
//  InspectorEngine.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/10/26.
//

import Foundation
import Observation

@Observable
final class InspectorEngine {
    let pid: Int32
    
    init() {
        self.pid = getpid()
    }
}
