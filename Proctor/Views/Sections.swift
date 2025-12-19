import SwiftUI

struct StatusBadge: View {
    let status: CollectorStatus

    var color: Color {
        switch status.state {
        case .ok: return .green
        case .partial: return .orange
        case .failed: return .red
        }
    }

    var body: some View {
        HStack(spacing: 6) {
            Circle().fill(color).frame(width: 10, height: 10)
            Text(status.state.rawValue.capitalized)
        }
    }
}

struct KeyValueRow: View {
    let title: String
    let value: String

    var body: some View {
        HStack {
            Text(title).font(.headline)
            Spacer()
            Text(value).foregroundStyle(.secondary)
        }
    }
}
