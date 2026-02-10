//
//  ProcessTrustInspectorApp.swift
//  ProcessTrustInspector
//
//  Application entry point for macOS Process Trust Inspector.
//
//  Responsibilities:
//  - Define the app’s primary window scene.
//  - Integrate with standard macOS application commands.
//  - Provide a native About panel using system conventions.
//
//  Design notes:
//  - The About panel uses macOS’s standard presentation to remain
//    consistent with platform expectations.
//  - No custom About window or additional UI is introduced for v1.
//
//  Created by Aaron Weiss on 1/10/26.
//

import SwiftUI
import AppKit

@main
struct ProcessTrustInspectorApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
        .commands {
            // Replace the default About item with a customized one.
            CommandGroup(replacing: .appInfo) {
                Button("About macOS Process Trust Inspector") {
                    showAboutPanel()
                }
            }
        }
    }

    /// Presents the standard macOS About panel with minimal,
    /// explanation-first metadata.
    private func showAboutPanel() {
        NSApplication.shared.orderFrontStandardAboutPanel(
            options: [
                .applicationName: "macOS Process Trust Inspector",
                .credits: NSAttributedString(
                    string: """
                Helpful process identity inspection for macOS.
                Created by Aaron Weiss.
                """)
            ]
        )
    }
}
