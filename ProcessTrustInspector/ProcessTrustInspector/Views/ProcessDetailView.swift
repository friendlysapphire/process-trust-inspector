//
//  ProcessDetailView.swift
//  Process Trust Inspector
//
//  Purpose:
//  Renders the explanation-first narrative for a selected process.
//
//  Responsibilities:
//  - Displays summary, trust classification, and narrative sections
//  - Applies consistent visual treatment for facts, limits, and uncertainty
//  - Handles layout and text behavior for readability
//
//  Non-Responsibilities:
//  - Performing inspection or interpretation
//  - Mutating engine state
//
//  Notes:
//  - Text truncation and wrapping are intentionally managed to favor clarity
//  - This view assumes narrative content is already validated by the engine
//

import SwiftUI
import AppKit

private enum LabelKeys {
    static let quarantineMetadata = "quarantine metadata"
    static let gatekeeperApplicability = "gatekeeper applicability"
    static let gatekeeperRelevance = "gatekeeper relevance"
    static let quarantineDetailLabels: Set<String> = [
        "quarantine agent",
        "first observed",
        "event identifier"
    ]
}

/// Renders the explanation-first narrative for a selected process.
///
/// `ProcessDetailView` is a pure view over `EngineNarrative`.
/// It assumes inspection, trust evaluation, and narrative construction
/// have already occurred in the engine layer.
///
/// Responsibilities:
/// - Present the narrative summary, classification, and section cards.
/// - Favor readability: wrapping, selection, and predictable layout.
/// - Render limits/uncertainty as first-class UI content.
///
/// Non-responsibilities:
/// - No system inspection.
/// - No interpretation of trust signals beyond what is provided in the models.
/// - No mutation of engine state.
struct ProcessDetailView: View {
    let narrative: EngineNarrative
    
    var body: some View {
        ScrollView {
            HStack(alignment: .top) {
                VStack(alignment: .leading, spacing: 20) {
                    
                    // Narrative summary (primary product)
                    if !narrative.summary.isEmpty {
                        VStack(alignment: .leading, spacing: 8) {
                            Text("Summary")
                                .font(.caption)
                                .foregroundColor(.secondary)
                            
                            // Single Text node so drag-selection works naturally.
                            Text(styledSummaryText(from: narrative.summary))
                                .font(.body)
                        }
                        .cardShell(material: .thinMaterial)
                    }
                    
                    // Trust Classification (orientation, not verdict)
                    VStack(alignment: .leading, spacing: 10) {
                        Text("Trust Classification")
                            .font(.headline)
                        
                        Text(narrative.trustClassification.label)
                            .font(.headline)
                            .fontWeight(.semibold)
                            .padding(.vertical, 6)
                            .padding(.horizontal, 10)
                            .background(.ultraThinMaterial)
                            .cornerRadius(8)
                        
                        if !narrative.trustClassification.interpretation.isEmpty {
                            Text(narrative.trustClassification.interpretation.joined(separator: "\n"))
                                .font(.body)
                                .fixedSize(horizontal: false, vertical: true)
                                .frame(maxWidth: .infinity, alignment: .leading)
                                .padding(.top, 2)
                        }
                        
                        if !narrative.trustClassification.evidence.isEmpty {
                            VStack(alignment: .leading, spacing: 8) {
                                Text("Evidence")
                                    .font(.footnote)
                                    .foregroundColor(.secondary)

                                ForEach(narrative.trustClassification.evidence) { fact in
                                    FactRow(fact: fact)
                                }
                            }
                            .padding(.top, 6)
                        }
                        
                        if !narrative.trustClassification.limits.isEmpty {
                            LimitList(limits: narrative.trustClassification.limits, wrapForLongLines: false)
                            .padding(.top, 2)
                        }
                    }
                    .cardShell(material: .thinMaterial)
                    
                    // Narrative sections
                    ForEach(narrative.sections) { section in
                        SectionCard(section: section)
                    }
                    
                    // Global limits (always visible)
                    if !narrative.globalLimits.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            Text("Limits & Uncertainty")
                                .font(.footnote)
                                .foregroundColor(.secondary)

                            LimitList(limits: narrative.globalLimits, wrapForLongLines: false)
                        }
                        .padding(.top, 4)
                    }
                    
                    Spacer(minLength: 0)
                }
                .padding(16)
                .frame(maxWidth: 720, alignment: .leading)
                .textSelection(.enabled)
                
                Spacer() // <-- key: makes ScrollView fill the pane, not just the 720pt column
            }
            .frame(maxWidth: .infinity, alignment: .leading) // optional but helps the layout
        }
        .navigationTitle(narrative.title)
    }
    
    // MARK: - Summary styling (single Text node; no string changes)
    
    private func styledSummaryText(from lines: [String]) -> AttributedString {
        // Exact header strings produced by NarrativeBuilder (no colons).
        let headerLines: Set<String> = [
            "Overview",
            "Runtime constraints",
            "Provenance"
        ]
        
        var result = AttributedString()
        
        for (idx, rawLine) in lines.enumerated() {
            let isHeader = headerLines.contains(rawLine)
            
            var line = AttributedString(rawLine)
            if isHeader {
                line.font = .headline
            } else {
                line.font = .body
            }
            
            // Preserve your existing blank line separation.
            result.append(line)
            
            if idx < lines.count - 1 {
                result.append(AttributedString("\n\n"))
            }
        }
        
        return result
    }
}

/// A reusable card view for a single narrative section.
///
/// `SectionCard` renders a section title, a brief explanatory subtitle
/// (interpretation), the section facts (via specialized blocks when needed),
/// and the section limits.
///
/// It intentionally contains only lightweight routing logic to choose
/// specialized renderers for well-known sections (e.g. Provenance).
/// It does not compute or reinterpret trust meaning.
private struct SectionCard: View {
    let section: NarrativeSection

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(section.title)
                .font(.headline)

            // Move the "what this is" sentence to the top as a subtle subtitle.
            if !section.interpretation.isEmpty {
                Text(section.interpretation.joined(separator: "\n"))
                    .font(.body)
                    .fixedSize(horizontal: false, vertical: true)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .padding(.top, 2)
            }

            if section.key == .runtimeConstraints {
                RuntimeConstraintsBlock(facts: section.facts)
            } else if section.key == .provenance {
                ProvenanceBlock(facts: section.facts)
            } else if !section.facts.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(section.facts) { fact in
                        FactRow(fact: fact)
                    }
                }
            }

            if !section.limits.isEmpty {
                LimitList(limits: section.limits, wrapForLongLines: true)
                .padding(.top, 2)
            }
        }
        .cardShell(material: .regularMaterial)
    }
}

// MARK: - Runtime Constraints
/// UI-level status used to render runtime constraint facts.
///
/// This is derived from `FactLine` values (e.g. "Yes"/"No") plus unknown reasons.
/// It is a rendering convenience and should not be treated as additional evidence.
private enum RuntimeConstraintStatus: Equatable {
    case enabled
    case disabled
    case unknown(reason: String?)
}

/// Renders the Runtime Constraints section as rows with brief explanations.
///
/// This block is UI-only: it maps `FactLine` values into a scannable layout
/// and surfaces unknown reasons without attempting additional interpretation.
private struct RuntimeConstraintsBlock: View {
    let facts: [FactLine]

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ForEach(facts) { fact in
                RuntimeConstraintRow(label: fact.label, status: status(from: fact))
            }
        }
    }

    private func status(from fact: FactLine) -> RuntimeConstraintStatus {
        if let value = fact.value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty {
            if value.caseInsensitiveCompare("Yes") == .orderedSame { return .enabled }
            if value.caseInsensitiveCompare("No") == .orderedSame { return .disabled }
            return .unknown(reason: value)
        }
        if let reason = fact.unknownReason, !reason.isEmpty {
            return .unknown(reason: reason)
        }
        return .unknown(reason: nil)
    }
}

/// Renders a single runtime-constraint row with an icon, label, and optional explanation.
///
/// The row may include:
/// - A short “what this means” helper text (product copy).
/// - An unknown reason when the underlying signal could not be obtained.
///
/// It also provides copy actions for user ergonomics.
private struct RuntimeConstraintRow: View {
    let label: String
    let status: RuntimeConstraintStatus

    private var explanationText: String? {
        let k = label.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()

        if k == "app sandbox" {
            return "A restricted execution environment that limits what the app can access unless explicitly allowed."
        }

        if k == "hardened runtime" {
            return "A code-signing mode that enables additional runtime protections and is commonly required for notarization."
        }

        return nil
    }
    
    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                statusIcon
                Text(label)
                    .font(.body)
                    .fontWeight(.medium)
                Spacer()
            }

            if let expl = explanationText {
                Text(expl)
                    .font(.callout)
                    .foregroundColor(.secondary)
                    .padding(.leading, 28)
            }

            if case .unknown(let reason) = status, let reason, !reason.isEmpty {
                Text(reason)
                    .font(.callout)
                    .foregroundColor(.secondary)
                    .padding(.leading, 28)
            }
        }
        .textSelection(.disabled)
        .contextMenu {
            Button("Copy Value") {
                copyToPasteboard(copyValueText())
            }

            Button("Copy Label + Value") {
                copyToPasteboard("\(label): \(copyValueText())")
            }

            if let r = copyReasonText() {
                Divider()
                Button("Copy Unknown Reason") {
                    copyToPasteboard(r)
                }
            }
        }
    }

    // MARK: - Copy helpers (UI only)

    private func copyValueText() -> String {
        switch status {
        case .enabled:
            return "Yes"
        case .disabled:
            return "No"
        case .unknown(let reason):
            if let reason = reason?.trimmingCharacters(in: .whitespacesAndNewlines), !reason.isEmpty {
                return "Unknown (\(reason))"
            }
            return "Unknown"
        }
    }

    private func copyReasonText() -> String? {
        guard case .unknown(let reason) = status else { return nil }
        guard let reason = reason?.trimmingCharacters(in: .whitespacesAndNewlines), !reason.isEmpty else { return nil }
        return reason
    }

    @ViewBuilder
    private var statusIcon: some View {
        switch status {
        case .enabled:
            Image(systemName: "checkmark.circle.fill")
                .foregroundColor(.green)
        case .disabled:
            Image(systemName: "xmark.circle.fill")
                .foregroundColor(.red)
        case .unknown:
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Provenance
/// UI-level status used to render provenance facts.
///
/// Provenance signals mix observed metadata (e.g. quarantine xattr) with
/// inferred applicability (e.g. Gatekeeper likelihood).
///
/// This enum exists to keep the UI explicit about what is observed vs inferred.
private enum ProvenanceStatus: Equatable {
    case present                  // ✅ observed
    case absent                   // ❌ observed absent
    case inferred(note: String?)  // ❓ conditional/inferred
    case unknown(reason: String?) // ⚠️ unavailable
}

/// Renders the Provenance section using provenance-specific semantics.
///
/// This block renders:
/// - Quarantine metadata as an observed present/absent/unknown signal.
/// - Gatekeeper applicability as an inferred note (unless unknown).
///
/// It is intentionally conservative: it does not claim Gatekeeper actually ran,
/// and it does not attempt notarization assessment.
private struct ProvenanceBlock: View {
    let facts: [FactLine]

    private var quarantineFact: FactLine? {
        facts.first(where: { normalizedLabel($0.label) == LabelKeys.quarantineMetadata })
    }

    private var gatekeeperFact: FactLine? {
        facts.first(where: {
            let k = normalizedLabel($0.label)
            return k == LabelKeys.gatekeeperApplicability || k == LabelKeys.gatekeeperRelevance
        })
    }

    private var quarantineDetailFacts: [FactLine] {
        facts.filter { LabelKeys.quarantineDetailLabels.contains(normalizedLabel($0.label)) }
    }

    private var remainingFacts: [FactLine] {
        var consumed = Set<UUID>()
        if let quarantineFact {
            consumed.insert(quarantineFact.id)
        }
        for fact in quarantineDetailFacts {
            consumed.insert(fact.id)
        }
        if let gatekeeperFact {
            consumed.insert(gatekeeperFact.id)
        }
        return facts.filter { !consumed.contains($0.id) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {

            // Quarantine: observed metadata present/absent/unknown
            if let q = quarantineFact {
                ProvenanceRow(
                    label: "Quarantine metadata",
                    status: quarantineStatus(from: q)
                )
            }

            // Group parsed quarantine fields under the main metadata row.
            ForEach(quarantineDetailFacts) { fact in
                FactRow(fact: fact)
                    .padding(.leading, 28)
            }

            // Gatekeeper: not directly observed in v1; treat as inferred applicability unless unknown
            if let gk = gatekeeperFact {
                ProvenanceRow(
                    label: "Gatekeeper applicability",
                    status: gatekeeperStatus(from: gk)
                )
            }

            // Render any additional facts generically so new provenance signals are not dropped.
            ForEach(remainingFacts) { fact in
                FactRow(fact: fact)
            }
        }
    }

    private func quarantineStatus(from fact: FactLine) -> ProvenanceStatus {
        if let value = fact.value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty {
            // Your UI uses "Present" / "Not present" for this fact right now.
            if value.lowercased().contains("present") && !value.lowercased().contains("not") { return .present }
            if value.lowercased().contains("not") { return .absent }
            return .unknown(reason: value)
        }
        if let reason = fact.unknownReason, !reason.isEmpty {
            return .unknown(reason: reason)
        }
        return .unknown(reason: nil)
    }

    private func gatekeeperStatus(from fact: FactLine) -> ProvenanceStatus {
        // If we couldn't compute relevance, show unknown.
        if let reason = fact.unknownReason, !reason.isEmpty {
            return .unknown(reason: reason)
        }

        // Otherwise treat the value as an inferred note (even if it says likely/possible/unlikely).
        let note = fact.value?.trimmingCharacters(in: .whitespacesAndNewlines)
        return .inferred(note: note)
    }
}

/// Renders a single provenance row with an icon, label, and optional note/reason.
///
/// The secondary line is used for:
/// - Inferred notes (e.g. “evaluation possible/unlikely…”), or
/// - Unknown reasons when provenance signals could not be determined.
///
/// Includes copy actions for the displayed value and supporting text.
private struct ProvenanceRow: View {
    let label: String
    let status: ProvenanceStatus

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                statusIcon
                Text(label)
                    .font(.body)
                    .fontWeight(.medium)
                Spacer()
            }

            // Show a short note/reason under the row when useful.
            switch status {
            case .inferred(let note):
                if let note, !note.isEmpty {
                    Text(note)
                        .font(.callout)
                        .foregroundColor(.secondary)
                        .padding(.leading, 28)
                }
            case .unknown(let reason):
                if let reason, !reason.isEmpty {
                    Text(reason)
                        .font(.callout)
                        .foregroundColor(.secondary)
                        .padding(.leading, 28)
                }
            default:
                EmptyView()
            }
        }
        .textSelection(.disabled)
        .contextMenu {
            Button("Copy Value") {
                copyToPasteboard(copyValueText())
            }

            Button("Copy Label + Value") {
                copyToPasteboard("\(label): \(copyValueText())")
            }

            if let extra = copyReasonOrNoteText() {
                Divider()
                Button(labelForReasonOrNote()) {
                    copyToPasteboard(extra)
                }
            }
        }
    }

    // MARK: - Copy helpers (UI only)

    private func copyValueText() -> String {
        switch status {
        case .present:
            return "Present"
        case .absent:
            return "Not present"
        case .inferred(let note):
            if let note = note?.trimmingCharacters(in: .whitespacesAndNewlines), !note.isEmpty {
                return note
            }
            return "Inferred"
        case .unknown(let reason):
            if let reason = reason?.trimmingCharacters(in: .whitespacesAndNewlines), !reason.isEmpty {
                return "Unknown (\(reason))"
            }
            return "Unknown"
        }
    }

    private func copyReasonOrNoteText() -> String? {
        switch status {
        case .inferred(let note):
            guard let note = note?.trimmingCharacters(in: .whitespacesAndNewlines), !note.isEmpty else { return nil }
            return note
        case .unknown(let reason):
            guard let reason = reason?.trimmingCharacters(in: .whitespacesAndNewlines), !reason.isEmpty else { return nil }
            return reason
        default:
            return nil
        }
    }

    private func labelForReasonOrNote() -> String {
        switch status {
        case .inferred:
            return "Copy Note"
        case .unknown:
            return "Copy Unknown Reason"
        default:
            return "Copy"
        }
    }

    @ViewBuilder
    private var statusIcon: some View {
        switch status {
        case .present:
            Image(systemName: "checkmark.circle.fill")
                .foregroundColor(.green)
        case .absent:
            Image(systemName: "xmark.circle.fill")
                .foregroundColor(.red)
        case .inferred:
            Image(systemName: "questionmark.circle.fill")
                .foregroundColor(.secondary)
        case .unknown:
            Image(systemName: "exclamationmark.triangle.fill")
                .foregroundColor(.secondary)
        }
    }
}

// MARK: - Fact rows (everything else)
/// Generic renderer for a `FactLine` (label + value + optional unknown reason).
///
/// This is used for most narrative facts outside specialized sections.
/// It favors readability for long values (paths) and preserves uncertainty
/// by surfacing unknown reasons directly in the UI.
private struct FactRow: View {
    let fact: FactLine

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .top, spacing: 10) {
                Text(fact.label + ":")
                    .foregroundColor(.secondary)
                    .frame(width: 170, alignment: .leading)

                Group {
                    if let value = fact.value, !value.isEmpty {
                        Text(value)
                            .fontWeight(.medium)
                            .fixedSize(horizontal: false, vertical: true) // <-- wrap paths
                    } else {
                        Text("Unknown")
                            .foregroundColor(.secondary)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)

                Spacer(minLength: 0)
            }

            if (fact.value == nil || fact.value?.isEmpty == true),
               let reason = fact.unknownReason,
               !reason.isEmpty {
                Text(reason)
                    .font(.callout)
                    .foregroundColor(.secondary)
                    .padding(.leading, 180)
            }
        }
        .textSelection(.disabled)
        .contextMenu {
            Button("Copy Value") {
                copyToPasteboard(copyValueText())
            }

            Button("Copy Label + Value") {
                copyToPasteboard("\(fact.label): \(copyValueText())")
            }

            if let reason = fact.unknownReason, !reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                Divider()
                Button("Copy Unknown Reason") {
                    copyToPasteboard(reason)
                }
            }
        }
    }

    // MARK: - Copy helpers (UI only)

    private func copyValueText() -> String {
        if let v = fact.value?.trimmingCharacters(in: .whitespacesAndNewlines), !v.isEmpty {
            return v
        }
        if let r = fact.unknownReason?.trimmingCharacters(in: .whitespacesAndNewlines), !r.isEmpty {
            return "Unknown (\(r))"
        }
        return "Unknown"
    }

}

private struct LimitList: View {
    let limits: [LimitNote]
    let wrapForLongLines: Bool

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            ForEach(limits, id: \.text) { limit in
                HStack(alignment: .top, spacing: 6) {
                    Text("•")
                        .font(.callout)
                        .foregroundColor(.secondary)

                    if wrapForLongLines {
                        Text(limit.text)
                            .font(.callout)
                            .foregroundColor(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .layoutPriority(1)
                    } else {
                        Text(limit.text)
                            .font(.callout)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
    }
}

private extension View {
    func cardShell(material: Material) -> some View {
        padding(12)
            .background(material)
            .cornerRadius(10)
    }
}

/// Centralized clipboard helper used by context menus in this file.
private func copyToPasteboard(_ text: String) {
    NSPasteboard.general.clearContents()
    NSPasteboard.general.setString(text, forType: .string)
}

/// Shared label canonicalization for section/fact matching in this file.
private func normalizedLabel(_ label: String) -> String {
    label.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
}
