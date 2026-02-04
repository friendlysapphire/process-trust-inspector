//
//  ProcessDetailView.swift
//  ProcessTrustInspector
//
//  Created by Aaron Weiss on 2/4/26.
//

import SwiftUI

struct ProcessDetailView: View {
    let process: ProcessSnapshot
    
    var body: some View {
        Form {
            Section(header: Text("Identity")) {
                DetailRow(label: "Name", value: process.name ?? "Unknown")
                DetailRow(label: "PID", value: "\(process.pid)")
                
                if let team = process.signingSummary?.teamID {
                    DetailRow(label: "Team ID", value: team)
                }
            }
            
            Section(header: Text("Trust Verdict")) {
                HStack {
                    Text(process.trustLevel.displayName)
                        .bold()
                    Spacer()
                }
                
                Text(process.trustLevel.explanation)
                    .font(.callout)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.top, 4)
            }
        }
        .navigationTitle(process.name ?? "Details")
        .padding()
    }
}

// A simple helper to avoid 'LabeledContent' compatibility issues
struct DetailRow: View {
    let label: String
    let value: String
    
    var body: some View {
        HStack {
            Text(label)
            Spacer()
            Text(value)
                .foregroundColor(.secondary)
        }
    }
}
