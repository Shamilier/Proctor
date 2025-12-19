import Foundation
import SwiftUI
import AppKit

final class SnapshotViewModel: ObservableObject {
    @Published var report: SnapshotReport
    @Published var isScanning = false
    @Published var searchText = ""
    @Published var timelineEnabled = false
    @Published var timeline: [TimelineEntry] = []

    private var timer: Timer?

    init() {
        let emptyStatus = CollectorStatus(state: .partial, errorMessage: "Not yet scanned")
        self.report = SnapshotReport(
            schemaVersion: "1.0.0",
            generatedAt: Date(),
            timeZone: TimeZone.current.identifier,
            device: CollectorPayload(status: emptyStatus, payload: nil),
            hardware: CollectorPayload(status: emptyStatus, payload: nil),
            runningApps: CollectorPayload(status: emptyStatus, payload: nil),
            runningProcesses: CollectorPayload(status: emptyStatus, payload: nil),
            permissions: CollectorPayload(status: emptyStatus, payload: nil),
            remoteServices: CollectorPayload(status: emptyStatus, payload: nil),
            listeningPorts: CollectorPayload(status: emptyStatus, payload: nil),
            displays: CollectorPayload(status: emptyStatus, payload: nil),
            risk: RiskAssessment(riskScore: 0, riskReasons: [], suspiciousApps: [], suspiciousProcesses: []),
            timeline: nil
        )
    }

    func scan() {
        isScanning = true
        DispatchQueue.global(qos: .userInitiated).async {
            let device = DeviceCollector.collect()
            let hardware = HardwareCollector.collect()
            let apps = AppsCollector.collect()
            let processes = ProcessesCollector.collect()
            let permissions = PermissionsCollector.collect()
            let services = RemoteServicesCollector.collectServices()
            let ports = RemoteServicesCollector.collectPorts()
            let displays = DisplaysCollector.collect()
            let risk = RiskEngine.evaluate(apps: apps.payload ?? [], processes: processes.payload ?? [])

            DispatchQueue.main.async {
                self.report = SnapshotReport(
                    schemaVersion: "1.0.0",
                    generatedAt: Date(),
                    timeZone: TimeZone.current.identifier,
                    device: device,
                    hardware: hardware,
                    runningApps: apps,
                    runningProcesses: processes,
                    permissions: permissions,
                    remoteServices: services,
                    listeningPorts: ports,
                    displays: displays,
                    risk: risk,
                    timeline: self.timelineEnabled ? self.timeline : nil
                )
                self.isScanning = false
            }
        }
    }

    func toggleTimeline(_ enabled: Bool) {
        timelineEnabled = enabled
        timer?.invalidate()
        if enabled {
            timer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
                self?.recordTimeline()
            }
        }
    }

    private func recordTimeline() {
        let currentFrontmost = NSWorkspace.shared.frontmostApplication
        let frontmostApp = currentFrontmost.map { app in
            RunningApp(name: app.localizedName ?? "Unknown",
                       bundleId: app.bundleIdentifier,
                       pid: Int(app.processIdentifier),
                       path: app.bundleURL?.path,
                       isActive: app.isActive,
                       isHidden: app.isHidden,
                       launchDate: app.launchDate,
                       kind: app.activationPolicy == .regular ? .uiApp : .agent,
                       teamIdentifier: nil)
        }
        let running = NSWorkspace.shared.runningApplications.map { app in
            RunningApp(name: app.localizedName ?? "Unknown",
                       bundleId: app.bundleIdentifier,
                       pid: Int(app.processIdentifier),
                       path: app.bundleURL?.path,
                       isActive: app.isActive,
                       isHidden: app.isHidden,
                       launchDate: app.launchDate,
                       kind: app.activationPolicy == .regular ? .uiApp : .agent,
                       teamIdentifier: nil)
        }
        let entry = TimelineEntry(timestamp: Date(), frontmostApp: frontmostApp, changedApps: running)
        DispatchQueue.main.async {
            self.timeline.append(entry)
            // keep last 10 minutes
            let tenMinutesAgo = Date().addingTimeInterval(-600)
            self.timeline = self.timeline.filter { $0.timestamp >= tenMinutesAgo }
        }
    }

    func exportReport() {
        let panel = NSSavePanel()
        panel.allowedFileTypes = ["json"]
        panel.nameFieldStringValue = "report.json"
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            self.saveReport(to: url)
        }
    }

    private func saveReport(to url: URL) {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        encoder.dateEncodingStrategy = .iso8601
        do {
            let data = try encoder.encode(report)
            try data.write(to: url)
        } catch {
            NSLog("Failed to export report: \(error)")
        }
    }

    func copyReportToClipboard() {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted]
        encoder.dateEncodingStrategy = .iso8601
        if let data = try? encoder.encode(report), let text = String(data: data, encoding: .utf8) {
            pasteboard.setString(text, forType: .string)
        }
    }

    func exportTimeline() {
        guard timelineEnabled else { return }
        let panel = NSSavePanel()
        panel.allowedFileTypes = ["jsonl"]
        panel.nameFieldStringValue = "timeline.jsonl"
        panel.begin { response in
            guard response == .OK, let url = panel.url else { return }
            self.saveTimeline(to: url)
        }
    }

    private func saveTimeline(to url: URL) {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        do {
            var lines: [String] = []
            for entry in timeline {
                let data = try encoder.encode(entry)
                if let line = String(data: data, encoding: .utf8) {
                    lines.append(line)
                }
            }
            try lines.joined(separator: "\n").write(to: url, atomically: true, encoding: .utf8)
        } catch {
            NSLog("Failed to export timeline: \(error)")
        }
    }
}
