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
            out.append(section.title)
            out.append(String(repeating: "-", count: section.title.count))

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
}

private extension FactLine {
    func asPlainTextLine() -> String {
        let v = (value?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
        if !v.isEmpty {
            return "\(label): \(v)"
        }
        let r = (unknownReason?.trimmingCharacters(in: .whitespacesAndNewlines) ?? "")
        if !r.isEmpty {
            return "\(label): Unknown (\(r))"
        }
        return "\(label): Unknown"
    }
}