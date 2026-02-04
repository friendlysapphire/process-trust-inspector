import SwiftUI

struct ProcessDetailView: View {
    let process: ProcessSnapshot

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {

                // Primary: narrative
                VStack(alignment: .leading, spacing: 6) {
                    Text("Trust Classification")
                        .font(.caption)
                        .foregroundColor(.secondary)

                    Text(process.trustLevel.explanation)
                        .font(.body)

                    Text(process.trustLevel.displayName)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .padding(12)

                // Secondary: identity details
                VStack(alignment: .leading, spacing: 8) {
                    Text("Identity")
                        .font(.headline)

                    DetailRow(label: "Name", value: process.name ?? "Unknown")
                    DetailRow(label: "PID", value: "\(process.pid)")

                    if let team = process.signingSummary?.teamID {
                        DetailRow(label: "Team ID", value: team)
                    }
                }
                .padding(12)
                .background(.regularMaterial)
                .cornerRadius(10)

                Spacer(minLength: 0)
            }
            .padding(16)
            .frame(maxWidth: 720, alignment: .leading) // keeps text readable on huge panes
        }
        .navigationTitle(process.name ?? "Details")
    }
    
    struct DetailRow: View {
        let label: String
        let value: String

        var body: some View {
            HStack(alignment: .firstTextBaseline) {
                Text(label + ":")
                    .foregroundColor(.secondary)
                    .frame(width: 80, alignment: .leading)

                Text(value)
                    .fontWeight(.medium)

                Spacer()
            }
        }
    }
}

