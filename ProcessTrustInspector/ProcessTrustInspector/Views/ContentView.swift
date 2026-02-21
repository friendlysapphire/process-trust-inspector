//
//  ContentView.swift
//  ProcessTrustInspector
//
//  Primary application shell and process list UI.
//
//  Responsibilities:
//  - Own the top-level navigation split view (process list ↔ detail view).
//  - Present the filtered, searchable list of running processes.
//  - Coordinate selection state with InspectorEngine.
//  - Surface refresh state and high-level trust categorization.
//
//  Design notes:
//  - This view does not perform inspection or interpretation.
//    All process analysis is delegated to InspectorEngine.
//  - UI logic here is intentionally lightweight and reactive,
//    favoring clarity over extensibility for v1.
//  - Sorting, filtering, and search are treated as a single,
//    explicit pipeline for predictability.
//
//  Created by Aaron Weiss on 1/31/26.
//

import SwiftUI
import AppKit

/// Primary application shell and navigation root.
///
/// `ContentView` owns the top-level `NavigationSplitView`, presenting:
/// - The filtered, searchable list of running processes (sidebar)
/// - The detail narrative for the selected process (detail pane)
///
/// Responsibilities:
/// - Coordinate selection state with `InspectorEngine`.
/// - Apply user-driven filtering, searching, and sorting.
/// - Surface refresh timing and high-level trust categorization.
///
/// Non-responsibilities:
/// - No process inspection or trust evaluation.
/// - No narrative construction or interpretation logic.
/// - No persistence or long-lived state beyond the UI session.
struct ContentView: View {
    @State private var engine = InspectorEngine()
    @State private var selectedCategory: TrustFilter = .all
    @State private var searchText: String = ""

    /// User-facing trust category filters for the process list.
    ///
    /// `TrustFilter` maps simplified trust categories to UI filter controls.
    /// These categories reflect `TrustCategory` values produced by inspection,
    /// but do not introduce new interpretation or semantics.
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
    /// Unified pipeline for deriving the visible process list.
    ///
    /// Applies filtering, text search, and stable sorting in a single,
    /// explicit sequence to ensure predictable UI behavior.
    ///
    /// Order of operations:
    /// 1. Trust-category filter
    /// 2. Text search (name or bundle identifier)
    /// 3. Stable alphabetical sort (name → PID)
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
                let name = (p.name ?? "").lowercased()
                let bundle = (p.bundleIdentifier ?? "").lowercased()
                return name.contains(q) || bundle.contains(q)
            }
        }

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
                        .font(.footnote)
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
                            .monospacedDigit()
                    }
                    .padding(.top, 2)
                }
                .padding(.horizontal, 12)
                .padding(.top, 10)
                .padding(.bottom, 10)

                Divider()

                List(visibleProcesses, id: \.pid, selection: $engine.selectedPID) { process in
                    HStack {
                        ProcessIconView(
                            icon: process.icon,
                            fallbackSystemName: iconName(for: process.trustLevel),
                            fallbackColor: color(for: process.trustLevel)
                        )

                        VStack(alignment: .leading, spacing: 2) {
                            Text(process.name ?? "Unknown")
                                .font(.headline)

                            Text(process.trustLevel.displayName)
                                .font(.footnote)
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

                        if let pid = engine.selectedPID,
                           !visibleProcesses.contains(where: { $0.pid == pid }) {
                            engine.clearSelection()
                        }
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .help("Refresh the process list")
                }
                ToolbarItem(placement: .automatic) {
                    Button {
                        engine.copySelectedReportToClipboard()
                    } label: {
                        Label("Copy Report", systemImage: "doc.on.doc")
                    }
                    .help("Copy the full report for the selected process")
                    .disabled(engine.selectedNarrative == nil)
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

    /// Returns the fallback SF Symbol name for a given trust category.
    ///
    /// Used only when a real application icon is unavailable.
    /// The symbol choice is intentionally simple and symbolic,
    /// not a security signal.
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

    /// Returns the fallback tint color associated with a trust category.
    ///
    /// Colors are used purely for visual grouping and scannability.
    /// They do not encode severity, risk, or safety judgments.
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

/// Renders a small process icon for the process list.
///
/// Prefers the real application icon when available, falling back to
/// a system symbol with a category-specific tint when necessary.
///
/// Design notes:
/// - Icons are optically balanced to appear consistent in the list.
/// - This view is purely presentational and carries no semantic meaning.
private struct ProcessIconView: View {
    let icon: NSImage?
    let fallbackSystemName: String
    let fallbackColor: Color

    var body: some View {
        Group {
            if let icon {
                Image(nsImage: icon)
                    .resizable()
                    .scaledToFit()
                    .scaleEffect(1.15)   // 👈 optical compensation
            } else {
                Image(systemName: fallbackSystemName)
                    .renderingMode(.template)
                    .resizable()
                    .scaledToFit()
                    .foregroundColor(fallbackColor)
            }
        }
        .frame(width: 18, height: 18)
        .cornerRadius(4)
    }
}
