import SwiftUI
import AppKit

struct ContentView: View {
    @StateObject private var viewModel = SnapshotViewModel()

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            header
            TabView {
                overviewTab
                    .tabItem { Label("Overview", systemImage: "info.circle") }
                appsTab
                    .tabItem { Label("Apps", systemImage: "app") }
                processesTab
                    .tabItem { Label("Processes", systemImage: "terminal") }
                permissionsTab
                    .tabItem { Label("Permissions", systemImage: "lock.shield") }
                remoteTab
                    .tabItem { Label("Remote", systemImage: "antenna.radiowaves.left.and.right") }
                timelineTab
                    .tabItem { Label("Timeline", systemImage: "clock.arrow.circlepath") }
            }
        }
        .padding()
    }

    private var header: some View {
        HStack(spacing: 12) {
            Button(action: viewModel.scan) {
                Label("Scan Now", systemImage: viewModel.isScanning ? "hourglass" : "arrow.triangle.2.circlepath")
            }
            .disabled(viewModel.isScanning)

            Toggle("Continuous Monitoring", isOn: Binding(get: { viewModel.timelineEnabled }, set: { viewModel.toggleTimeline($0) }))
                .toggleStyle(.switch)
                .help("Record frontmost app and running apps every 2 seconds")

            Spacer()

            Button(action: viewModel.exportReport) { Label("Export Report", systemImage: "square.and.arrow.down") }
            Button(action: viewModel.copyReportToClipboard) { Label("Copy JSON", systemImage: "doc.on.doc") }
            Button(action: viewModel.exportTimeline) { Label("Export Timeline", systemImage: "clock.badge.arrow.circlepath") }
        }
    }

    private var overviewTab: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                HStack {
                    Text("System Snapshot & Risk Report").font(.title2).bold()
                    Spacer()
                    Text("Risk Score: \(viewModel.report.risk.riskScore)")
                        .font(.title3)
                        .padding(8)
                        .background(Capsule().fill(Color.blue.opacity(0.1)))
                }

                deviceSection
                hardwareSection
                riskSection
            }
        }
    }

    private var deviceSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Device").font(.headline)
                StatusBadge(status: viewModel.report.device.status)
            }
            if let device = viewModel.report.device.payload {
                KeyValueRow(title: "macOS", value: "\(device.macOSVersion) (\(device.buildVersion))")
                KeyValueRow(title: "Model", value: device.model)
                KeyValueRow(title: "Architecture", value: device.architecture)
                KeyValueRow(title: "Hostname", value: device.hostName)
                KeyValueRow(title: "Current User", value: device.currentUser)
                KeyValueRow(title: "Uptime", value: formatTime(device.uptime))
                if !device.activeUsers.isEmpty {
                    KeyValueRow(title: "Active Users", value: device.activeUsers.joined(separator: ", "))
                }
            } else {
                Text(viewModel.report.device.status.errorMessage ?? "No data")
            }
        }
    }

    private var hardwareSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack { Text("Hardware").font(.headline); StatusBadge(status: viewModel.report.hardware.status) }
            if let hardware = viewModel.report.hardware.payload {
                KeyValueRow(title: "CPU", value: "\(hardware.cpu.physicalCores)x cores / \(hardware.cpu.logicalCores)x logical")
                KeyValueRow(title: "Load Avg", value: hardware.cpu.loadAverage.map { String(format: "%.2f", $0) }.joined(separator: ", "))
                KeyValueRow(title: "Memory", value: "Used \(formatBytes(hardware.memory.used)) of \(formatBytes(hardware.memory.total))")
                KeyValueRow(title: "Disk", value: "Free \(formatBytes(hardware.disk.free)) of \(formatBytes(hardware.disk.total))")
                if !hardware.disk.mountPoints.isEmpty {
                    Text("Mounts: \(hardware.disk.mountPoints.prefix(3).joined(separator: ", "))")
                }
                if let percentage = hardware.battery.percentage {
                    KeyValueRow(title: "Battery", value: String(format: "%.0f%%", percentage))
                }
                if !hardware.networkInterfaces.isEmpty {
                    ForEach(hardware.networkInterfaces) { iface in
                        KeyValueRow(title: iface.name, value: "\(iface.type) @ \(iface.address) \(iface.ssid ?? "")")
                    }
                }
            } else {
                Text(viewModel.report.hardware.status.errorMessage ?? "No data")
            }
        }
    }

    private var riskSection: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Risk Indicators").font(.headline)
            if viewModel.report.risk.riskReasons.isEmpty {
                Text("No suspicious indicators detected.")
            } else {
                ForEach(viewModel.report.risk.riskReasons) { reason in
                    HStack {
                        Text(reason.category).bold()
                        Text(reason.message)
                        Spacer()
                        Text("+\(reason.score)")
                    }
                }
            }
        }
    }

    private var appsTab: some View {
        VStack(alignment: .leading) {
            HStack {
                TextField("Search apps", text: $viewModel.searchText)
                StatusBadge(status: viewModel.report.runningApps.status)
            }
            List(filteredApps) { app in
                VStack(alignment: .leading) {
                    HStack {
                        Text(app.name).font(.headline)
                        if let bundle = app.bundleId { Text(bundle).foregroundStyle(.secondary) }
                        Spacer()
                        Text("PID: \(app.pid)").foregroundStyle(.secondary)
                    }
                    if let path = app.path { Text(path).font(.footnote).foregroundStyle(.secondary) }
                }
            }
        }
        .padding(.top, 8)
    }

    private var processesTab: some View {
        VStack(alignment: .leading) {
            HStack { Text("Processes").font(.headline); StatusBadge(status: viewModel.report.runningProcesses.status) }
            List(filteredProcesses) { process in
                VStack(alignment: .leading) {
                    HStack {
                        Text(process.command).font(.headline)
                        Spacer()
                        Text("PID: \(process.pid)")
                        Text("PPID: \(process.parentPid)")
                    }
                    Text(process.arguments).font(.footnote).foregroundStyle(.secondary)
                }
            }
        }
    }

    private var permissionsTab: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack { Text("Permissions").font(.headline); StatusBadge(status: viewModel.report.permissions.status) }
            if let permissions = viewModel.report.permissions.payload {
                ForEach(permissions) { permission in
                    HStack {
                        VStack(alignment: .leading) {
                            Text(permission.kind).font(.headline)
                            Text(permission.explanation).font(.footnote).foregroundStyle(.secondary)
                        }
                        Spacer()
                        Text(permission.isAuthorized ? "Granted" : "Not Granted")
                            .padding(6)
                            .background(Capsule().fill(permission.isAuthorized ? Color.green.opacity(0.2) : Color.orange.opacity(0.2)))
                    }
                }
            } else {
                Text(viewModel.report.permissions.status.errorMessage ?? "No data")
            }
        }
    }

    private var remoteTab: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack { Text("Remote Services").font(.headline); StatusBadge(status: viewModel.report.remoteServices.status) }
            if let services = viewModel.report.remoteServices.payload {
                ForEach(services) { service in
                    HStack {
                        Text(service.name)
                        Spacer()
                        if let enabled = service.isEnabled {
                            Text(enabled ? "Enabled" : "Disabled")
                        }
                        if let note = service.note { Text(note).font(.footnote).foregroundStyle(.secondary) }
                    }
                }
            }

            Divider()
            HStack { Text("Listening Ports").font(.headline); StatusBadge(status: viewModel.report.listeningPorts.status) }
            if let ports = viewModel.report.listeningPorts.payload {
                ForEach(ports) { port in
                    HStack {
                        Text("\(port.protocolType) \(port.address):\(port.port)")
                        Spacer()
                    }
                }
            } else if let error = viewModel.report.listeningPorts.status.errorMessage {
                Text(error)
            }
        }
    }

    private var timelineTab: some View {
        VStack(alignment: .leading, spacing: 8) {
            Toggle("Continuous Monitoring", isOn: Binding(get: { viewModel.timelineEnabled }, set: { viewModel.toggleTimeline($0) }))
            if viewModel.timelineEnabled {
                List(viewModel.timeline) { entry in
                    VStack(alignment: .leading) {
                        Text(entry.timestamp, style: .time)
                        if let front = entry.frontmostApp {
                            Text("Frontmost: \(front.name) [\(front.bundleId ?? "-")]")
                        }
                        Text("Running count: \(entry.changedApps.count)").font(.footnote)
                    }
                }
            } else {
                Text("Enable timeline to begin capturing foreground activity.")
            }
        }
    }

    private var filteredApps: [RunningApp] {
        let apps = viewModel.report.runningApps.payload ?? []
        guard !viewModel.searchText.isEmpty else { return apps }
        return apps.filter { $0.name.lowercased().contains(viewModel.searchText.lowercased()) || ($0.bundleId ?? "").lowercased().contains(viewModel.searchText.lowercased()) }
    }

    private var filteredProcesses: [RunningProcess] {
        let processes = viewModel.report.runningProcesses.payload ?? []
        guard !viewModel.searchText.isEmpty else { return processes }
        return processes.filter { $0.command.lowercased().contains(viewModel.searchText.lowercased()) || $0.arguments.lowercased().contains(viewModel.searchText.lowercased()) }
    }

    private func formatTime(_ interval: TimeInterval) -> String {
        let formatter = DateComponentsFormatter()
        formatter.allowedUnits = [.day, .hour, .minute]
        formatter.unitsStyle = .abbreviated
        return formatter.string(from: interval) ?? "-"
    }

    private func formatBytes(_ bytes: UInt64) -> String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useGB, .useMB]
        formatter.countStyle = .binary
        return formatter.string(fromByteCount: Int64(bytes))
    }
}

#Preview {
    ContentView()
}
