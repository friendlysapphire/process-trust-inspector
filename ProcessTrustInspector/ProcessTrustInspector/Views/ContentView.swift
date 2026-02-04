//
//  ContentView.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/31/26.
//

import SwiftUI
import AppKit

struct ContentView: View {
    @State private var processes: [ProcessSnapshot] = []
    private let inspector = ProcessInspector()

    @State private var selectedCategory: TrustFilter = .all
    @State private var selectedPID: Int32? = nil   // adjust if your pid type differs

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
            return processes
        case .apple:
            return processes.filter { $0.trustLevel == .apple }
        case .thirdParty:
            return processes.filter { $0.trustLevel == .appStore || $0.trustLevel == .developer }
        case .unsigned:
            return processes.filter { $0.trustLevel == .unsigned }
        }
    }

    private var selectedProcess: ProcessSnapshot? {
        guard let pid = selectedPID else { return nil }
        return processes.first { $0.pid == pid }
    }

    var body: some View {
        NavigationSplitView {
            // Sidebar (filters always visible + list)
            VStack(spacing: 0) {
                // A “mac-like” sidebar header area
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
                
                List(filteredProcesses, id: \.pid, selection: $selectedPID) { process in
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
            if let process = selectedProcess {
                ProcessDetailView(process: process)
            } else {
                Text("Select a process to inspect")
                    .foregroundColor(.secondary)
            }
        }
        .onAppear {
            loadProcesses()
            if let pid = selectedPID, !filteredProcesses.contains(where: { $0.pid == pid }) {
                selectedPID = nil
            }
        }
        .onChange(of: selectedCategory) { _, _ in
            if let pid = selectedPID,
               !filteredProcesses.contains(where: { $0.pid == pid }) {
                selectedPID = nil
            }
        }

    }

    private func loadProcesses() {
        let apps = NSWorkspace.shared.runningApplications
        var snapshots: [ProcessSnapshot] = []

        for app in apps {
            if let snapshot = inspector.getProcessSnapshot(from: app.processIdentifier) {
                snapshots.append(snapshot)
            }
        }

        self.processes = snapshots.sorted { ($0.name ?? "") < ($1.name ?? "") }
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

