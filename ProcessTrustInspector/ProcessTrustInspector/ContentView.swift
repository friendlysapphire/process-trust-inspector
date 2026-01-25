//
//  ContentView.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 1/10/26.
//

import SwiftUI

struct ContentView: View {
    
    @State private var engine = InspectorEngine()
    
    var body: some View {
        VStack(alignment: .leading){
            
            HStack {
                Button("Refresh") {
                    engine.refresh()
                }
            }
            HStack {
                Text("Refreshes:")
                Text("\(engine.refreshCount)")
            }
            
            HStack {
                Text("Running Application Count:")
                Text("\(engine.runningAppCount)")
            }
            
            Divider()
            
            Text("Running Apps")
                .font(.headline)
           
            ScrollView {
                VStack(alignment: .leading, spacing: 6) {
                    ForEach(engine.runningAppList) { row in
                        VStack(alignment: .leading) {
                            Text("\(row.pName ?? "Unknown") (\(row.pPid))")
                            Text(row.pBundleIdentifier ?? "—")
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        } .onTapGesture { engine.select(pid: row.id) }
                          .background(engine.selectedPID == row.id ? Color.gray.opacity(0.15) : Color.clear)
                        
                        Divider()
                    }
                }
            }
            .frame(minHeight: 200)
            
            Divider()

            Text("Selected Process")
                .font(.headline)

            Text(engine.selectionExplanationText)
                .font(.caption)
                .foregroundStyle(.secondary)

            Divider()
                .padding(.vertical, 6)
            
            Text("General")
                .font(.subheadline)
            
            if let s = engine.selectedSnapshot {
                Text("PID: \(s.pPid)")
                Text("Name: \(s.pName ?? "Unknown")")
                Text("Bundle ID: \(s.pBundleIdentifier ?? "—")")
                Text("Executable Path: \(s.pExecutablePath?.path() ?? "Unknown")")
                
                Divider()
                    .padding(.vertical, 6)
                
                Text("Signing")
                    .font(.subheadline)
                
                if let signing = s.pSigningSummary {
                    Text("OSStatus: \(signing.status)")
                    Text("Identifier: \(signing.identifier ?? "—")")
                    Text("Team ID: \(signing.teamID ?? "—")")
                } else {
                        Text("Signing info unavailable.")
                            .foregroundStyle(.secondary)
                    }
            } else {
                Text("Click a running app to inspect it.")
                    .foregroundStyle(.secondary)
            }



        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

#Preview {
    ContentView()
}
