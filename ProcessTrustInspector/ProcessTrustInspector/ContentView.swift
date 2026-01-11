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
                Text("PID:")
                Text("\(engine.pid)")
            }
            HStack {
                Text("Process Name:")
                Text("\(engine.processName)")
                    .lineLimit(nil)
                    .multilineTextAlignment(.leading)
                
            }
            HStack {
                Text("Bundle ID:")
                Text("\(engine.bundleIdentifier)")
            }
            HStack {
                Text("Execution Path:")
                Text("\(engine.execPath)")
                    .lineLimit(nil)
                    .multilineTextAlignment(.leading)
            }
            
            Divider()
            
            
            HStack {
                Text("Running Application Count:")
                Text("\(engine.runningAppCount)")
            }
            HStack {
                Text("First Running App:")
                Text("\(engine.firstRunningApp)")
            }
            HStack(alignment: .top) {
                Text("Full Running Apps List:")
                ScrollView {
                    Text("\(engine.runningAppsListText)")
                        .lineLimit(nil)
                        .fixedSize(horizontal: false, vertical: true)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .multilineTextAlignment(.leading)
                }
                .frame(maxWidth: .infinity, minHeight: 200, alignment: .leading)
            }
        }
        .padding()
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}

#Preview {
    ContentView()
}
