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
                        }
                        Divider()
                    }
                }
            }
            .frame(minHeight: 200)


        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

#Preview {
    ContentView()
}
