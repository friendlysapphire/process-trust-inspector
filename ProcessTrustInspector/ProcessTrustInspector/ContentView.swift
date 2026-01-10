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
            Image(systemName: "globe")
                .imageScale(.large)
                .foregroundStyle(.tint)
            Text("PID: \(engine.pid)")
            Text("Process Name: \(engine.processName)")
        }
        .padding()
    }
}

#Preview {
    ContentView()
}
