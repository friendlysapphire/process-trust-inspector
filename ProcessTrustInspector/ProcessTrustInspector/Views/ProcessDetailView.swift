import SwiftUI
import AppKit

struct ProcessDetailView: View {
    let narrative: EngineNarrative

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {

                // Narrative summary (primary product)
                if !narrative.summary.isEmpty {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Summary")
                            .font(.caption)
                            .foregroundColor(.secondary)

                        // Single Text node so drag-selection works naturally.
                        Text(narrative.summary.joined(separator: "\n\n"))
                            .font(.body)
                    }
                    .padding(12)
                    .background(.thinMaterial)
                    .cornerRadius(10)
                }

                // Trust Classification (orientation, not verdict)
                VStack(alignment: .leading, spacing: 10) {
                    Text("Trust Classification")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Text(narrative.trustClassification.label)
                        .font(.headline)

                    if !narrative.trustClassification.interpretation.isEmpty {
                        Text(narrative.trustClassification.interpretation.joined(separator: "\n"))
                            .font(.body)
                            .padding(.top, 2)
                    }

                    if !narrative.trustClassification.evidence.isEmpty {
                        DisclosureGroup("Evidence") {
                            VStack(alignment: .leading, spacing: 8) {
                                ForEach(narrative.trustClassification.evidence) { fact in
                                    FactRow(fact: fact)
                                }
                            }
                            .padding(.top, 8)
                        }
                        .font(.subheadline)
                    }

                    if !narrative.trustClassification.limits.isEmpty {
                        Text(narrative.trustClassification.limits.map { "• \($0.text)" }.joined(separator: "\n"))
                            .font(.footnote)
                            .foregroundColor(.secondary)
                            .padding(.top, 2)
                    }
                }
                .padding(12)
                .background(.thinMaterial)
                .cornerRadius(10)

                // Narrative sections
                ForEach(narrative.sections) { section in
                    SectionCard(section: section)
                }

                // Global limits (always visible)
                if !narrative.globalLimits.isEmpty {
                    VStack(alignment: .leading, spacing: 6) {
                        Text("Limits & Uncertainty")
                            .font(.caption)
                            .foregroundColor(.secondary)

                        Text(narrative.globalLimits.map { "• \($0.text)" }.joined(separator: "\n"))
                            .font(.footnote)
                            .foregroundColor(.secondary)
                    }
                    .padding(.top, 4)
                }

                Spacer(minLength: 0)
            }
            .padding(16)
            .frame(maxWidth: 720, alignment: .leading)
            .textSelection(.enabled)
        }
        .navigationTitle(narrative.title)
    }
}

private struct SectionCard: View {
    let section: NarrativeSection

    private var isRuntimeConstraintsSection: Bool {
        let normalized = section.title.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if normalized == "runtime constraints" || normalized == "runtime constraint" || normalized == "runtime" {
            return true
        }
        let labels = Set(section.facts.map { $0.label.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })
        return labels.contains("app sandbox") || labels.contains("hardened runtime")
    }

    private var isProvenanceSection: Bool {
        let normalized = section.title.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if normalized == "provenance" { return true }
        let labels = Set(section.facts.map { $0.label.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })
        return labels.contains("quarantine metadata") || labels.contains("gatekeeper relevance")
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(section.title)
                .font(.headline)

            if isRuntimeConstraintsSection {
                RuntimeConstraintsBlock(facts: section.facts)
            } else if isProvenanceSection {
                ProvenanceBlock(facts: section.facts)
            } else if !section.facts.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    ForEach(section.facts) { fact in
                        FactRow(fact: fact)
                    }
                }
            }

            if !section.interpretation.isEmpty {
                Text(section.interpretation.joined(separator: "\n"))
                    .font(.body)
                    .padding(.top, 2)
            }

            if !section.limits.isEmpty {
                Text(section.limits.map { "• \($0.text)" }.joined(separator: "\n"))
                    .font(.footnote)
                    .foregroundColor(.secondary)
                    .padding(.top, 2)
            }
        }
        .padding(12)
        .background(.regularMaterial)
        .cornerRadius(10)
    }
}

// MARK: - Runtime Constraints

private enum RuntimeConstraintStatus: Equatable {
    case enabled
    case disabled
    case unknown(reason: String?)
}

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

private struct RuntimeConstraintRow: View {
    let label: String
    let status: RuntimeConstraintStatus

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                statusIcon
                Text(label)
                    .font(.body)
                    .fontWeight(.medium)
                Spacer()
            }

            if case .unknown(let reason) = status, let reason, !reason.isEmpty {
                Text(reason)
                    .font(.footnote)
                    .foregroundColor(.secondary)
                    .padding(.leading, 28)
            }
        }
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

    private func copyToPasteboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
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

private enum ProvenanceStatus: Equatable {
    case present            // ✅ observed
    case absent             // ❌ observed absent
    case inferred(note: String?) // ❓ conditional/inferred
    case unknown(reason: String?) // ⚠️ unavailable
}

private struct ProvenanceBlock: View {
    let facts: [FactLine]

    private var quarantineFact: FactLine? {
        facts.first(where: { $0.label.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "quarantine metadata" })
    }

    private var gatekeeperFact: FactLine? {
        facts.first(where: { $0.label.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() == "gatekeeper relevance" })
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

            // Gatekeeper: not directly observed in v1; treat as inferred applicability unless unknown
            if let gk = gatekeeperFact {
                ProvenanceRow(
                    label: "Gatekeeper checks",
                    status: gatekeeperStatus(from: gk)
                )
            }

            // A+ explicit epistemology note (small, calm, always the same)
            Text("Gatekeeper checks are inferred from context and metadata. They are not directly observed here, and missing quarantine metadata does not confirm whether Gatekeeper ran.")
                .font(.footnote)
                .foregroundColor(.secondary)
                .padding(.top, 2)
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
                        .font(.footnote)
                        .foregroundColor(.secondary)
                        .padding(.leading, 28)
                }
            case .unknown(let reason):
                if let reason, !reason.isEmpty {
                    Text(reason)
                        .font(.footnote)
                        .foregroundColor(.secondary)
                        .padding(.leading, 28)
                }
            default:
                EmptyView()
            }
        }
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

    private func copyToPasteboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
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
private struct FactRow: View {
    let fact: FactLine

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(alignment: .firstTextBaseline, spacing: 10) {
                Text(fact.label + ":")
                    .foregroundColor(.secondary)
                    .frame(width: 170, alignment: .leading)

                if let value = fact.value, !value.isEmpty {
                    Text(value)
                        .fontWeight(.medium)
                } else {
                    Text("Unknown")
                        .foregroundColor(.secondary)
                }

                Spacer()
            }

            if (fact.value == nil || fact.value?.isEmpty == true),
               let reason = fact.unknownReason,
               !reason.isEmpty {
                Text(reason)
                    .font(.footnote)
                    .foregroundColor(.secondary)
                    .padding(.leading, 180)
            }
        }
        .textSelection(.enabled)
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

    private func copyToPasteboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }
}
