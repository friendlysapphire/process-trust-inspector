import SwiftUI

struct ProcessDetailView: View {
    let narrative: EngineNarrative

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {

                // Trust Classification (orientation, not verdict)
                VStack(alignment: .leading, spacing: 8) {
                    Text("Trust Classification")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Text(narrative.trustClassification.label)
                        .font(.headline)

                    if !narrative.trustClassification.interpretation.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(narrative.trustClassification.interpretation, id: \.self) { line in
                                Text(line)
                                    .font(.body)
                            }
                        }
                    }

                    if !narrative.trustClassification.evidence.isEmpty {
                        DisclosureGroup("Evidence") {
                            VStack(alignment: .leading, spacing: 6) {
                                ForEach(narrative.trustClassification.evidence) { fact in
                                    FactRow(fact: fact)
                                }
                            }
                            .padding(.top, 6)
                        }
                        .font(.subheadline)
                    }

                    if !narrative.trustClassification.limits.isEmpty {
                        VStack(alignment: .leading, spacing: 4) {
                            ForEach(narrative.trustClassification.limits) { limit in
                                Text("• \(limit.text)")
                                    .font(.footnote)
                                    .foregroundColor(.secondary)
                            }
                        }
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

                        ForEach(narrative.globalLimits) { limit in
                            Text("• \(limit.text)")
                                .font(.footnote)
                                .foregroundColor(.secondary)
                        }
                    }
                    .padding(.top, 4)
                }

                Spacer(minLength: 0)
            }
            .padding(16)
            .frame(maxWidth: 720, alignment: .leading)
        }
        .navigationTitle(narrative.title)
    }
}

private struct SectionCard: View {
    let section: NarrativeSection

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(section.title)
                .font(.headline)

            if !section.facts.isEmpty {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(section.facts) { fact in
                        FactRow(fact: fact)
                    }
                }
            }

            if !section.interpretation.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(section.interpretation, id: \.self) { line in
                        Text(line)
                            .font(.body)
                    }
                }
            }

            if !section.limits.isEmpty {
                VStack(alignment: .leading, spacing: 4) {
                    ForEach(section.limits) { limit in
                        Text("• \(limit.text)")
                            .font(.footnote)
                            .foregroundColor(.secondary)
                    }
                }
            }
        }
        .padding(12)
        .background(.regularMaterial)
        .cornerRadius(10)
    }
}

private struct FactRow: View {
    let fact: FactLine

    var body: some View {
        HStack(alignment: .firstTextBaseline, spacing: 8) {
            Text(fact.label + ":")
                .foregroundColor(.secondary)
                .frame(width: 140, alignment: .leading)

            Text(fact.displayValue)
                .fontWeight(.medium)

            Spacer()
        }
    }
}

