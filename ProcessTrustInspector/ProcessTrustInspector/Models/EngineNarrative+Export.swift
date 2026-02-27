//
//  EngineNarrative+Export.swift
//  ProcessTrustInspector
//
//  Purpose:
//  Export-friendly renderings of an EngineNarrative.
//
//  Notes:
//  - Pure formatting only (no OS calls, no UI code).
//  - Intended for copy/export features (v1.2+).
//

import Foundation

extension EngineNarrative {

    func asPlainText() -> String {
        var out: [String] = []

        out.append(title)
        out.append("")

        // Summary
        if !summary.isEmpty {
            out.append("Summary")
            out.append(String(repeating: "=", count: 7))
            out.append(contentsOf: summary)
            out.append("")
        }

        // Trust classification
        out.append("Trust Classification: \(trustClassification.label)")
        if !trustClassification.interpretation.isEmpty {
            out.append("")
            out.append("Interpretation")
            out.append(contentsOf: trustClassification.interpretation)
        }
        if !trustClassification.evidence.isEmpty {
            out.append("")
            out.append("Evidence")
            out.append(contentsOf: trustClassification.evidence.map { $0.asPlainTextLine() })
        }
        if !trustClassification.limits.isEmpty {
            out.append("")
            out.append("Limits")
            out.append(contentsOf: trustClassification.limits.map { "- \($0.text)" })
        }
        out.append("")

        // Sections
        for section in sections {
            let sectionTitle = section.exportTitle
            out.append(sectionTitle)
            out.append(String(repeating: "-", count: sectionTitle.count))

            if !section.interpretation.isEmpty {
                out.append("")
                out.append(contentsOf: section.interpretation)
            }

            if !section.facts.isEmpty {
                out.append("")
                out.append("Facts")
                out.append(contentsOf: section.facts.map { $0.asPlainTextLine() })
            }

            if !section.limits.isEmpty {
                out.append("")
                out.append("Limits")
                out.append(contentsOf: section.limits.map { "- \($0.text)" })
            }

            out.append("")
        }

        // Global limits
        if !globalLimits.isEmpty {
            out.append("Limits & Uncertainty")
            out.append(String(repeating: "-", count: 19))
            out.append(contentsOf: globalLimits.map { "- \($0.text)" })
            out.append("")
        }

        // Trim trailing blank lines
        while out.last == "" { _ = out.popLast() }

        return out.joined(separator: "\n")
    }
    
    func asMarkdown() -> String {
        var out: [String] = []

        // Title
        out.append("# \(title)")
        out.append("")

        // Summary
        if !summary.isEmpty {
            out.append("## Summary")
            out.append("")
            for line in summary {
                out.append("- \(line)")
            }
            out.append("")
        }

        // Trust Classification
        out.append("## Trust Classification")
        out.append("")
        out.append("**\(trustClassification.label)**")
        out.append("")

        if !trustClassification.interpretation.isEmpty {
            for line in trustClassification.interpretation {
                out.append(line)
            }
            out.append("")
        }

        if !trustClassification.evidence.isEmpty {
            out.append("### Evidence")
            out.append("")
            for fact in trustClassification.evidence {
                out.append("- \(fact.asMarkdownLine())")
            }
            out.append("")
        }

        if !trustClassification.limits.isEmpty {
            out.append("### Limits")
            out.append("")
            for limit in trustClassification.limits {
                out.append("- \(limit.text)")
            }
            out.append("")
        }

        // Sections
        for section in sections {
            out.append("## \(section.exportTitle)")
            out.append("")

            if !section.interpretation.isEmpty {
                for line in section.interpretation {
                    out.append(line)
                }
                out.append("")
            }

            if !section.facts.isEmpty {
                for fact in section.facts {
                    out.append("- \(fact.asMarkdownLine())")
                }
                out.append("")
            }

            if !section.limits.isEmpty {
                out.append("### Limits")
                out.append("")
                for limit in section.limits {
                    out.append("- \(limit.text)")
                }
                out.append("")
            }
        }

        // Global limits
        if !globalLimits.isEmpty {
            out.append("## Limits & Uncertainty")
            out.append("")
            for limit in globalLimits {
                out.append("- \(limit.text)")
            }
            out.append("")
        }

        while out.last == "" { _ = out.popLast() }

        return out.joined(separator: "\n")
    }
}


private extension FactLine {
    func asPlainTextLine() -> String {
        let v = (value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
        if !v.isEmpty {
            return "\(exportLabel): \(v)"
        }
        let r = (unknownReason?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
        if !r.isEmpty {
            return "\(exportLabel): Unknown (\(r))"
        }
        return "\(exportLabel): Unknown"
    }
}

private extension FactLine {
    func asMarkdownLine() -> String {
        let v = (value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
        if !v.isEmpty {
            return "**\(exportLabel):** \(v)"
        }
        let r = (unknownReason?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
        if !r.isEmpty {
            return "**\(exportLabel):** Unknown (\(r))"
        }
        return "**\(exportLabel):** Unknown"
    }
}

private extension NarrativeSection {
    var exportTitle: String {
        switch key {
        case .runtimeConstraints:
            return "Runtime Constraints"
        case .provenance:
            return "Provenance"
        default:
            return title
        }
    }
}

private extension FactLine {
    var exportLabel: String {
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
            return label
        }
    }
}
