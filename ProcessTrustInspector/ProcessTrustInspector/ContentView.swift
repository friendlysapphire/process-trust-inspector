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
        VStack {
            Button("Refresh") {
                engine.refresh()
            }
            
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("PID: \(engine.pid)")
            Text("Process Name: \(engine.processName)")
            Text("Refreshes: \(engine.refreshCount)")
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
