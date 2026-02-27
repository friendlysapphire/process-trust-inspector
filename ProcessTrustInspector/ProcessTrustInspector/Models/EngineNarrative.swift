//
//  EngineNarrativeModels.swift
//  ProcessTrustInspector
//
//  UI-facing output models: structured narrative + fact blocks.
//
//  This file defines the “render contract” produced by InspectorEngine.
//  Views render these models; they do not interpret trust signals or
//  recompute meaning.
//
//  Responsibilities:
//  - Provide stable, structured types for Narrative Mode rendering.
//  - Represent facts + unknown reasons without forcing UI string parsing.
//  - Carry explicit limits/uncertainty at both section and global scope.
//
//  Non-responsibilities:
//  - No OS inspection logic (handled by inspectors/engines).
//  - No UI layout or formatting logic (handled by Views).
//  - No trust evaluation rules (handled by signing/inspection components).
//
//  Notes:
//  - These models are intentionally simple and “best-effort friendly”.
//    Missing data should be represented explicitly as unknown, not inferred.
//
//

import Foundation

// MARK: - Top-level narrative output

/// The complete, structured narrative output for a selected process.
///
/// `EngineNarrative` is the primary product of the inspection engine.
/// It represents everything the UI needs to render Narrative Mode:
/// a summary, a trust orientation block, detailed sections, and
/// global limits describing scope and uncertainty.
///
/// This model is explanation-first and intentionally avoids
/// security verdicts or risk scoring.
struct EngineNarrative {
    /// Title to use for navigation / header (usually process name, best-effort).
    var title: String
    
    /// Narrative Mode: human-readable summary shown before sections.
    var summary: [String] = []
    
    /// High-level orientation. Not a verdict.
    var trustClassification: TrustClassificationBlock
    
    /// Sectioned narrative: Identity, Code Signing, etc.
    var sections: [NarrativeSection]
    
    /// Always-visible, global caveats about scope and uncertainty.
    var globalLimits: [LimitNote] = []
    
    init(
        title: String,
        trustClassification: TrustClassificationBlock,
        sections: [NarrativeSection],
        summary: [String] = [],
        globalLimits: [LimitNote] = []
    ) {
        self.title = title
        self.trustClassification = trustClassification
        self.sections = sections
        self.summary = summary
        self.globalLimits = globalLimits
    }
}

// MARK: - Trust Classification

/// High-level trust orientation for the selected executable.
///
/// This block answers the question:
/// “What kind of software is this, based on static identity signals?”
///
/// It is not a safety verdict. It exists to orient the reader before
/// diving into detailed sections and evidence.
struct TrustClassificationBlock {
    /// A short label (e.g. “Apple Software”, “3rd Party, Developer ID”, “Unsigned / Untrusted”).
    var label: String

    /// Concrete observed facts that support the label (optional but recommended).
    var evidence: [FactLine] = []

    /// Short explanation of what the label tends to imply (not prose polish).
    var interpretation: [String] = []

    /// What this classification does *not* prove.
    var limits: [LimitNote] = []

    init(
        label: String,
        evidence: [FactLine] = [],
        interpretation: [String] = [],
        limits: [LimitNote] = []
    ) {
        self.label = label
        self.evidence = evidence
        self.interpretation = interpretation
        self.limits = limits
    }
}

// MARK: - Sections

/// A structured explanatory section within the narrative.
///
/// Each section groups:
/// - Observed or derived facts
/// - Interpretation explaining what those facts tend to mean
/// - Explicit limits describing what is not proven or observed
///
/// Sections are designed to be independently readable and
/// epistemically honest.
struct NarrativeSection: Identifiable {
    let id = UUID()

    var key: NarrativeSectionKey = .unknown
    var title: String
    var facts: [FactLine] = []
    var interpretation: [String] = []
    var limits: [LimitNote] = []

    init(
        key: NarrativeSectionKey = .unknown,
        title: String,
        facts: [FactLine] = [],
        interpretation: [String] = [],
        limits: [LimitNote] = []
    ) {
        self.key = key
        self.title = title
        self.facts = facts
        self.interpretation = interpretation
        self.limits = limits
    }
}

enum NarrativeSectionKey: String {
    case identity
    case processLineage
    case codeSigning
    case provenance
    case runtimeConstraints
    case unknown
}

// MARK: - Facts & Uncertainty

/// A single factual statement with optional uncertainty.
///
/// `FactLine` represents a concrete data point that may be:
/// - Known (with a value)
/// - Unknown (with an explicit reason)
///
/// This structure avoids forcing the UI to infer meaning from
/// empty strings or sentinel values.
struct FactLine: Identifiable {
    let id = UUID()

    var key: FactLineKey = .unknown
    var label: String
    var value: String?
    var unknownReason: String?

    init(key: FactLineKey = .unknown, label: String, value: String?, unknownReason: String? = nil) {
        self.key = key
        self.label = label
        self.value = value
        self.unknownReason = unknownReason
    }

    /// Convenience for UI rendering when you want a single string.
    var displayValue: String {
        if let value, !value.isEmpty {
            return value
        }
        if let unknownReason, !unknownReason.isEmpty {
            return "Unknown (\(unknownReason))"
        }
        return "Unknown"
    }

    /// Helper for “known/unknown” checks without string parsing.
    var isKnown: Bool {
        if let value { return !value.isEmpty }
        return false
    }
}

enum FactLineKey: String {
    case runtimeAppSandbox
    case runtimeHardenedRuntime
    case provenanceQuarantineMetadata
    case provenanceQuarantineAgent
    case provenanceQuarantineFirstObserved
    case provenanceQuarantineEventIdentifier
    case provenanceGatekeeperApplicability
    case unknown
}

enum NarrativeDisplayCopy {
    static let provenanceDetailFactKeys: Set<FactLineKey> = [
        .provenanceQuarantineAgent,
        .provenanceQuarantineFirstObserved,
        .provenanceQuarantineEventIdentifier
    ]

    static func sectionTitle(for key: NarrativeSectionKey, fallback: String) -> String {
        switch key {
        case .runtimeConstraints:
            return "Runtime Constraints"
        case .provenance:
            return "Provenance"
        default:
            return fallback
        }
    }

    static func factLabel(for key: FactLineKey, fallback: String) -> String {
        switch key {
        case .runtimeAppSandbox:
            return "App Sandbox"
        case .runtimeHardenedRuntime:
            return "Hardened Runtime"
        case .provenanceQuarantineMetadata:
            return "Quarantine metadata"
        case .provenanceQuarantineAgent:
            return "Quarantine agent"
        case .provenanceQuarantineFirstObserved:
            return "First observed"
        case .provenanceQuarantineEventIdentifier:
            return "Event identifier"
        case .provenanceGatekeeperApplicability:
            return "Gatekeeper applicability"
        default:
            return fallback
        }
    }

    static func runtimeExplanation(for key: FactLineKey) -> String? {
        switch key {
        case .runtimeAppSandbox:
            return "A restricted execution environment that limits what the app can access unless explicitly allowed."
        case .runtimeHardenedRuntime:
            return "A code-signing mode that enables additional runtime protections and is commonly required for notarization."
        default:
            return nil
        }
    }
}

/// A non-alarmist statement describing uncertainty or scope limits.
///
/// `LimitNote` is used to explicitly communicate what a section
/// or the entire tool does *not* establish, helping prevent
/// over-interpretation of partial signals.
struct LimitNote: Identifiable {
    let id = UUID()
    var text: String

    init(text: String) {
        self.text = text
    }
}
