//
//  InspectorEngine+Export.swift
//  ProcessTrustInspector
//
//  UI-facing export and clipboard helpers for engine narratives.
//

import Foundation
import AppKit
import UniformTypeIdentifiers

extension InspectorEngine {

    func copySelectedReportToClipboard() {
        guard let narrative = selectedNarrative else { return }
        let text = narrative.asPlainText()
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    @MainActor
    func exportSelectedReportAsMarkdown() {

        guard let narrative = selectedNarrative else { return }

        let panel = NSSavePanel()

        if let mdType = UTType(filenameExtension: "md") {
            panel.allowedContentTypes = [mdType]
        }

        panel.nameFieldStringValue = "process-report.md"
        panel.canCreateDirectories = true

        if panel.runModal() == .OK, let url = panel.url {
            do {
                try narrative.asMarkdown().write(to: url, atomically: true, encoding: .utf8)
            } catch {
                print("Failed to export markdown: \(error)")
            }
        }
    }
}
