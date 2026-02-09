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
    @State private var searchText: String = ""

    enum TrustFilter: String, CaseIterable, Identifiable {
        case all = "All"
        case apple = "Apple"
        case thirdParty = "3rd Party"
        case unsigned = "No Publisher Identity"
        case unknown = "Signature Check Failed"

        var id: String { self.rawValue }
    }

    private var lastRefreshDisplay: String {
        guard let t = engine.lastRefreshTime else { return "Never" }
        return t.formatted(date: .abbreviated, time: .shortened)
    }

    // MARK: - Unified list pipeline (filter → search → sort)
    private var visibleProcesses: [ProcessSnapshot] {
        let base: [ProcessSnapshot]
        switch selectedCategory {
        case .all:
            base = engine.processes
        case .apple:
            base = engine.processes.filter { $0.trustLevel == .apple }
        case .thirdParty:
            base = engine.processes.filter { $0.trustLevel == .appStore || $0.trustLevel == .developer }
        case .unsigned:
            base = engine.processes.filter { $0.trustLevel == .unsigned }
        case .unknown:
            base = engine.processes.filter { $0.trustLevel == .unknown }
        }

        let trimmedQuery = searchText.trimmingCharacters(in: .whitespacesAndNewlines)
        let searched: [ProcessSnapshot]
        if trimmedQuery.isEmpty {
            searched = base
        } else {
            let q = trimmedQuery.lowercased()
            searched = base.filter { p in
                // Keep it simple + forgiving: name OR bundle id match.
                let name = (p.name ?? "").lowercased()
                let bundle = (p.bundleIdentifier ?? "").lowercased()
                return name.contains(q) || bundle.contains(q)
            }
        }

        // Alpha sort: name (case-insensitive) then PID to stabilize ordering.
        return searched.sorted {
            let aName = ($0.name ?? "Unknown").lowercased()
            let bName = ($1.name ?? "Unknown").lowercased()
            if aName == bName { return $0.pid < $1.pid }
            return aName < bName
        }
    }

    var body: some View {
        NavigationSplitView {
            VStack(spacing: 0) {
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

                    HStack(spacing: 6) {
                        Text("Last refresh:")
                            .font(.caption)
                            .foregroundColor(.secondary)

                        Text(lastRefreshDisplay)
                            .font(.caption)
                            .foregroundColor(.secondary)
                    }
                    .padding(.top, 2)
                }
                .padding(.horizontal, 12)
                .padding(.top, 10)
                .padding(.bottom, 10)

                Divider()

                List(visibleProcesses, id: \.pid, selection: $engine.selectedPID) { process in
                    HStack {
                        Image(systemName: iconName(for: process.trustLevel))
                            .foregroundColor(color(for: process.trustLevel))

                        VStack(alignment: .leading, spacing: 2) {
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
                .searchable(text: $searchText, placement: .sidebar, prompt: "Search processes")
            }
            .navigationTitle("Process Inspector")
            .toolbar {
                ToolbarItem(placement: .automatic) {
                    Button {
                        engine.refresh()

                        // Refresh might invalidate selection.
                        if let pid = engine.selectedPID,
                           !visibleProcesses.contains(where: { $0.pid == pid }) {
                            engine.clearSelection()
                        }
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .help("Refresh the process list")
                }
            }
        } detail: {
            if let narrative = engine.selectedNarrative {
                ProcessDetailView(narrative: narrative)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
            } else {
                Text("Select a process to inspect")
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .center)
            }
        }
        .onAppear {
            engine.refresh()

            if let pid = engine.selectedPID,
               !visibleProcesses.contains(where: { $0.pid == pid }) {
                engine.clearSelection()
            }
        }
        .onChange(of: engine.selectedPID) { _, newValue in
            if let pid = newValue {
                engine.select(pid: pid)
            } else {
                engine.clearSelection()
            }
        }
        .onChange(of: selectedCategory) { _, _ in
            if let pid = engine.selectedPID,
               !visibleProcesses.contains(where: { $0.pid == pid }) {
                engine.clearSelection()
            }
        }
        .onChange(of: searchText) { _, _ in
            if let pid = engine.selectedPID,
               !visibleProcesses.contains(where: { $0.pid == pid }) {
                engine.clearSelection()
            }
        }
    }

    private func iconName(for category: TrustCategory) -> String {
        switch category {
        case .apple:
            return "applelogo"
        case .appStore:
            return "checkmark.seal.fill"
        case .developer:
            return "person.crop.circle.badge.checkmark"
        case .unsigned:
            return "exclamationmark.triangle.fill"
        case .unknown:
            return "questionmark.circle.fill"
        }
    }

    private func color(for category: TrustCategory) -> Color {
        switch category {
        case .apple:
            return .gray
        case .appStore, .developer:
            return .blue
        case .unsigned:
            return .orange
        case .unknown:
            return .secondary
        }
    }
}
