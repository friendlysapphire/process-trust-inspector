//
//  ParentProcessInfo.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 2/15/26.
//


//
//  ContextModels.swift
//  ProcessTrustInspector
//
//  Cross-cutting context models shared between the Engine and Narrative layers.
//
//  This file contains lightweight data structures that represent
//  derived contextual information about a process, such as lineage
//  relationships or structural observations that are not intrinsic
//  properties of ProcessSnapshot itself.
//
//  Responsibilities:
//  - Model derived, engine-computed context (e.g., parent visibility).
//  - Preserve uncertainty explicitly (unknown-with-reason).
//  - Provide stable, interpretation-ready structures for NarrativeBuilder.
//
//  Non-responsibilities:
//  - No OS inspection logic.
//  - No UI rendering logic.
//  - No trust re-interpretation inside Views.
//
//  These types act as coordination contracts between the inspection
//  pipeline and the narrative layer.
//
import Foundation

/// Describes what is known about a process’s parent at the time of inspection.
///
/// This model separates three distinct states:
/// - No parent PID was available (metadata missing or inaccessible).
/// - A parent PID exists but is not visible in the current enumeration scope.
/// - A parent snapshot is available and can be compared contextually.
///
/// This distinction prevents silent assumptions and allows the narrative
/// layer to explain lineage uncertainty explicitly.
    enum ParentProcessInfo {
        case noParentPID(reason: String?)
        case parentNotVisible(pid: pid_t, reason: String?)
        case parentAvailable(parent: ProcessSnapshot)
    }
