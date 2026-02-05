//
//  EngineNarrativeModels.swift
//  ProcessTrustInspector
//
//  output model: structured narrative + fact blocks.
//  This is the UI-facing contract produced by the Engine.
//  Views render this; they do not interpret trust or recompute meaning.
//

import Foundation

// MARK: - Top-level narrative output

/// The Engine’s complete, structured explanation for a selected process.
/// This is the single object the UI should render in Narrative Mode.
struct EngineNarrative {
    /// Title to use for navigation / header (usually process name, best-effort).
    var title: String

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
        globalLimits: [LimitNote] = []
    ) {
        self.title = title
        self.trustClassification = trustClassification
        self.sections = sections
        self.globalLimits = globalLimits
    }
}

// MARK: - Trust Classification

/// Top-of-detail orientation block.
/// Keeps the tool calm and explanatory: “what kind of thing is this, based on what we can see?”
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

/// A section is the fundamental unit of explanation.
/// Every section must carry: facts, interpretation, limits.
struct NarrativeSection: Identifiable {
    let id = UUID()

    var title: String
    var facts: [FactLine] = []
    var interpretation: [String] = []
    var limits: [LimitNote] = []

    init(
        title: String,
        facts: [FactLine] = [],
        interpretation: [String] = [],
        limits: [LimitNote] = []
    ) {
        self.title = title
        self.facts = facts
        self.interpretation = interpretation
        self.limits = limits
    }
}

// MARK: - Facts & Uncertainty

/// A single factual line, optionally unknown with a reason.
/// This supports both Narrative Mode (readable) and future Evidence Mode (structured fields).
struct FactLine: Identifiable {
    let id = UUID()

    var label: String
    var value: String?
    var unknownReason: String?

    init(label: String, value: String?, unknownReason: String? = nil) {
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

/// A calm, non-alarmist caveat.
/// Used both per-section (“limits”) and globally (“Limits & Uncertainty”).
struct LimitNote: Identifiable {
    let id = UUID()
    var text: String

    init(text: String) {
        self.text = text
    }
}
