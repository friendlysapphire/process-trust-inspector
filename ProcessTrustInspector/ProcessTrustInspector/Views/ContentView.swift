//
//  ContentView.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/31/26.
//

import SwiftUI
import AppKit

struct ContentView: View {
    @State private var engine = InspectorEngine()

    @State private var selectedCategory: TrustFilter = .all

    enum TrustFilter: String, CaseIterable, Identifiable {
        case all = "All"
        case apple = "Apple"
        case thirdParty = "3rd Party"
        case unsigned = "Unsigned"
        var id: String { self.rawValue }
    }

    private var filteredProcesses: [ProcessSnapshot] {
        switch selectedCategory {
        case .all:
            return engine.processes
        case .apple:
            return engine.processes.filter { $0.trustLevel == .apple }
        case .thirdParty:
            return engine.processes.filter { $0.trustLevel == .appStore || $0.trustLevel == .developer }
        case .unsigned:
            return engine.processes.filter { $0.trustLevel == .unsigned }
        }
    }

    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
                // Sidebar header (filters always visible)
                VStack(alignment: .leading, spacing: 8) {
                    Text("Filter")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Picker("Filter", selection: $selectedCategory) {
                        ForEach(TrustFilter.allCases) { category in
                            Text(category.rawValue).tag(category)
                        }
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                    .controlSize(.small)
                }
                .padding(.horizontal, 12)
                .padding(.top, 10)
                .padding(.bottom, 10)

                Divider()

                // Sidebar list driven entirely by engine snapshot list
                List(filteredProcesses, id: \.pid, selection: $engine.selectedPID) { process in
                    HStack {
                        Image(systemName: iconName(for: process.trustLevel))
                            .foregroundColor(color(for: process.trustLevel))

                        VStack(alignment: .leading) {
                            Text(process.name ?? "Unknown")
                                .font(.headline)
                            Text(process.trustLevel.displayName)
                                .font(.caption)
                                .foregroundColor(.secondary)
                        }
                    }
                    .tag(process.pid)
                }
                .listStyle(.sidebar)
            }
            .navigationTitle("Process Inspector")
        } detail: {
            if let process = engine.selectedSnapshot {
                ProcessDetailView(process: process)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            } else {
                Text("Select a process to inspect")
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
            }
        }
        .onAppear {
            // If you want an explicit refresh on launch, keep this.
            // If you prefer engine.init() to be the only refresh, you can remove this call.
            engine.refresh()

            // If current selection is hidden by the filter, clear it.
            if let pid = engine.selectedPID,
               !filteredProcesses.contains(where: { $0.pid == pid }) {
                engine.clearSelection()
            }
        }
        // When user selects a row, drive selection through the engine
        .onChange(of: engine.selectedPID) { _, newValue in
            if let pid = newValue {
                engine.select(pid: pid)
            } else {
                engine.clearSelection()
            }
        }
        // If filter changes and hides the selected process, clear selection
        .onChange(of: selectedCategory) { _, _ in
            if let pid = engine.selectedPID,
               !filteredProcesses.contains(where: { $0.pid == pid }) {
                engine.clearSelection()
            }
        }
    }

    private func iconName(for category: TrustCategory) -> String {
        switch category {
        case .apple: return "applelogo"
        case .appStore: return "checkmark.seal.fill"
        case .developer: return "person.crop.circle.badge.checkmark"
        case .unsigned: return "exclamationmark.triangle.fill"
        }
    }

    private func color(for category: TrustCategory) -> Color {
        switch category {
        case .apple: return .gray
        case .appStore, .developer: return .blue
        case .unsigned: return .orange
        }
    }
}

