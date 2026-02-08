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
                
                List(filteredProcesses, id: \.pid, selection: $engine.selectedPID) { process in
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
            }
            .navigationTitle("Process Inspector")
            .toolbar {
                ToolbarItem(placement: .automatic) {
                    Button {
                        engine.refresh()
                        
                        // If refresh makes the current selection invalid, engine will clear it.
                        // But selection can also become hidden by the current filter; handle that.
                        if let pid = engine.selectedPID,
                           !filteredProcesses.contains(where: { $0.pid == pid }) {
                            engine.clearSelection()
                        }
                    } label: {
                        Label("Refresh", systemImage: "arrow.clockwise")
                    }
                    .help("Refresh the process list")
                }
            }
        } detail: {
            // Primary detail binding: Narrative model (Step 2 output contract)
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
               !filteredProcesses.contains(where: { $0.pid == pid }) {
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
               !filteredProcesses.contains(where: { $0.pid == pid }) {
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
