import Foundation
import AppKit
import AVFoundation
import CoreGraphics
import IOKit.ps
import IOKit
import Security
import Darwin

// Helper to execute shell commands safely
struct CommandRunner {
    static func run(_ command: String, arguments: [String]) -> String {
        let process = Process()
        process.launchPath = command
        process.arguments = arguments

        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = pipe

        do {
            try process.run()
        } catch {
            return ""
        }

        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(data: data, encoding: .utf8) ?? ""
    }
}

// MARK: Device Collector
struct DeviceCollector {
    static func collect() -> CollectorPayload<DeviceInfo> {
        var status = CollectorStatus(state: .ok, errorMessage: nil)
        let processInfo = ProcessInfo.processInfo
        let host = Host.current()
        let uptime = processInfo.systemUptime
        let version = processInfo.operatingSystemVersion
        let versionString = "macOS \(version.majorVersion).\(version.minorVersion).\(version.patchVersion)"
        let build = processInfo.operatingSystemVersionString

        var model = "Unknown"
        if let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice")),
           let modelData = IORegistryEntryCreateCFProperty(service, "model" as CFString, kCFAllocatorDefault, 0).takeRetainedValue() as? Data,
           let modelString = String(data: modelData, encoding: .utf8) {
            model = modelString.trimmingCharacters(in: .controlCharacters)
        }

        var architecture = "Unknown"
#if arch(x86_64)
        architecture = "Intel (x86_64)"
#elseif arch(arm64)
        architecture = "Apple Silicon (arm64)"
#endif

        let hostName = host.localizedName ?? processInfo.hostName
        let currentUser = NSUserName()
        let activeUsersOutput = CommandRunner.run("/usr/bin/who", arguments: [])
        let activeUsers = activeUsersOutput.split(separator: "\n").map { line in
            line.split(separator: " ").first.map(String.init) ?? String(line)
        }

        let info = DeviceInfo(macOSVersion: versionString,
                              buildVersion: build,
                              model: model,
                              architecture: architecture,
                              uptime: uptime,
                              hostName: hostName,
                              currentUser: currentUser,
                              activeUsers: activeUsers)

        return CollectorPayload(status: status, payload: info)
    }
}

// MARK: Hardware Collector
struct HardwareCollector {
    static func collect() -> CollectorPayload<HardwareResources> {
        var status = CollectorStatus(state: .ok, errorMessage: nil)

        let physicalCores = ProcessInfo.processInfo.processorCount
        let logicalCores = ProcessInfo.processInfo.activeProcessorCount
        var averages = [Double](repeating: 0.0, count: 3)
        if getloadavg(&averages, 3) != -1 {
            // values are already normalized to cores
        }
        let cpu = CPUInfo(physicalCores: physicalCores, logicalCores: logicalCores, loadAverage: averages)

        let totalMemory = ProcessInfo.processInfo.physicalMemory
        let pageSize = vm_kernel_page_size
        var vmStats = vm_statistics64()
        var count = UInt32(MemoryLayout<vm_statistics64_data_t>.size / MemoryLayout<integer_t>.size)
        let result = withUnsafeMutablePointer(to: &vmStats) { pointer -> kern_return_t in
            pointer.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics64(mach_host_self(), HOST_VM_INFO64, $0, &count)
            }
        }
        var free: UInt64 = 0
        var used: UInt64 = 0
        if result == KERN_SUCCESS {
            free = UInt64(vmStats.free_count) * UInt64(pageSize)
            let active = UInt64(vmStats.active_count + vmStats.inactive_count + vmStats.wire_count)
            used = active * UInt64(pageSize)
        }
        let memory = MemoryInfo(total: totalMemory, free: free, used: used)

        let fileManager = FileManager.default
        let home = fileManager.homeDirectoryForCurrentUser
        let values = try? home.resourceValues(forKeys: [.volumeTotalCapacityKey, .volumeAvailableCapacityKey])
        let total = UInt64(values?.volumeTotalCapacity ?? 0)
        let available = UInt64(values?.volumeAvailableCapacity ?? 0)
        let mountsOutput = CommandRunner.run("/sbin/mount", arguments: [])
        let mountPoints = mountsOutput.split(separator: "\n").map { line in
            let parts = line.split(separator: " " )
            return parts.count > 2 ? String(parts[2]) : String(line)
        }
        let disk = DiskInfo(total: total, free: available, mountPoints: mountPoints)

        var battery = BatteryInfo(percentage: nil, isCharging: nil, cycleCount: nil)
        if let blob = IOPSCopyPowerSourcesInfo()?.takeRetainedValue(),
           let sources = IOPSCopyPowerSourcesList(blob)?.takeRetainedValue() as? [CFTypeRef],
           let first = sources.first,
           let description = IOPSGetPowerSourceDescription(blob, first)?.takeUnretainedValue() as? [String: Any] {
            if let current = description[kIOPSCurrentCapacityKey] as? Double,
               let max = description[kIOPSMaxCapacityKey] as? Double {
                battery.percentage = (current / max) * 100.0
            }
            if let isCharging = description[kIOPSIsChargingKey] as? Bool {
                battery.isCharging = isCharging
            }
            if let cycles = description[kIOPSCycleCountKey] as? Int {
                battery.cycleCount = cycles
            }
        }

        var interfaces: [NetworkInterfaceInfo] = []
        let host = Host.current()
        if let addresses = host.addresses {
            for address in addresses {
                let type = address.contains(":") ? "IPv6" : "IPv4"
                interfaces.append(NetworkInterfaceInfo(name: "Interface", address: address, type: type, ssid: nil))
            }
        }

        let resources = HardwareResources(cpu: cpu, memory: memory, disk: disk, battery: battery, networkInterfaces: interfaces)
        return CollectorPayload(status: status, payload: resources)
    }
}

// MARK: Apps Collector
struct AppsCollector {
    static func collect() -> CollectorPayload<[RunningApp]> {
        var status = CollectorStatus(state: .ok, errorMessage: nil)
        let apps = NSWorkspace.shared.runningApplications.map { app -> RunningApp in
            let kind: RunningApp.Kind = app.activationPolicy == .regular ? .uiApp : .agent
            return RunningApp(name: app.localizedName ?? "Unknown",
                              bundleId: app.bundleIdentifier,
                              pid: Int(app.processIdentifier),
                              path: app.bundleURL?.path,
                              isActive: app.isActive,
                              isHidden: app.isHidden,
                              launchDate: app.launchDate,
                              kind: kind,
                              teamIdentifier: app.executableURL.flatMap { try? SecCodeCopySigningInformationForURL($0) })
        }
        return CollectorPayload(status: status, payload: apps)
    }
}

extension AppsCollector {
    // Pulls TeamIdentifier using Security without throwing fatal errors
    private static func SecCodeCopySigningInformationForURL(_ url: URL) -> String? {
        var staticCode: SecStaticCode?
        let status = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
        guard status == errSecSuccess, let code = staticCode else { return nil }
        var information: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(code, SecCSFlags(), &information)
        guard infoStatus == errSecSuccess, let info = information as? [String: Any] else { return nil }
        return info[kSecCodeInfoTeamIdentifier as String] as? String
    }
}

// MARK: Processes Collector
struct ProcessesCollector {
    static func collect() -> CollectorPayload<[RunningProcess]> {
        var status = CollectorStatus(state: .ok, errorMessage: nil)
        let output = CommandRunner.run("/bin/ps", arguments: ["-axo", "pid=,uid=,ppid=,comm=,args="])
        let lines = output.split(separator: "\n")
        let processes: [RunningProcess] = lines.compactMap { line in
            let parts = line.split(separator: " ", maxSplits: 4, omittingEmptySubsequences: true)
            guard parts.count >= 4 else { return nil }
            let pid = Int(parts[0]) ?? 0
            let uid = Int(parts[1]) ?? 0
            let ppid = Int(parts[2]) ?? 0
            let command = String(parts[3])
            let arguments = parts.count > 4 ? String(parts[4]) : ""
            return RunningProcess(pid: pid, command: command, arguments: arguments, uid: uid, parentPid: ppid)
        }
        return CollectorPayload(status: status, payload: processes)
    }
}

// MARK: Permissions Collector
struct PermissionsCollector {
    static func collect() -> CollectorPayload<[PermissionStatus]> {
        var items: [PermissionStatus] = []

        // Screen Recording
        let screenAuthorized = CGPreflightScreenCaptureAccess()
        items.append(PermissionStatus(kind: "Screen Recording", isAuthorized: screenAuthorized, explanation: "Required to capture screen for diagnostics.", requestable: true))

        // Accessibility
        let trusted = AXIsProcessTrusted()
        items.append(PermissionStatus(kind: "Accessibility", isAuthorized: trusted, explanation: "Needed for observing UI events.", requestable: true))

        // Microphone
        let micStatus = AVCaptureDevice.authorizationStatus(for: .audio)
        items.append(PermissionStatus(kind: "Microphone", isAuthorized: micStatus == .authorized, explanation: "Used to detect mic availability only.", requestable: micStatus == .notDetermined))

        // Camera
        let cameraStatus = AVCaptureDevice.authorizationStatus(for: .video)
        items.append(PermissionStatus(kind: "Camera", isAuthorized: cameraStatus == .authorized, explanation: "Used to detect camera availability only.", requestable: cameraStatus == .notDetermined))

        // Input Monitoring (best-effort)
        items.append(PermissionStatus(kind: "Input Monitoring", isAuthorized: false, explanation: "macOS does not expose a public API to query this permission.", requestable: false))

        let status = CollectorStatus(state: .ok, errorMessage: nil)
        return CollectorPayload(status: status, payload: items)
    }
}

// MARK: Remote Services Collector
struct RemoteServicesCollector {
    static func collectServices() -> CollectorPayload<[RemoteServiceStatus]> {
        var services: [RemoteServiceStatus] = []

        let remoteLoginOutput = CommandRunner.run("/usr/sbin/systemsetup", arguments: ["-getremotelogin"])
        let remoteLoginEnabled = remoteLoginOutput.lowercased().contains("on")
        services.append(RemoteServiceStatus(name: "Remote Login (SSH)", isEnabled: remoteLoginEnabled, note: remoteLoginOutput.trimmingCharacters(in: .whitespacesAndNewlines)))

        let screenSharingOutput = CommandRunner.run("/bin/launchctl", arguments: ["print", "system/com.apple.screensharing"])
        let screenSharingEnabled = screenSharingOutput.contains("state = running")
        services.append(RemoteServiceStatus(name: "Screen Sharing", isEnabled: screenSharingEnabled, note: "launchctl print system/com.apple.screensharing"))

        let ardOutput = CommandRunner.run("/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Resources/kickstart", arguments: ["-status"])
        let ardEnabled = ardOutput.lowercased().contains("active") || ardOutput.lowercased().contains("running")
        services.append(RemoteServiceStatus(name: "Remote Management (ARD)", isEnabled: ardEnabled, note: "kickstart -status"))

        let status = CollectorStatus(state: .ok, errorMessage: nil)
        return CollectorPayload(status: status, payload: services)
    }

    static func collectPorts() -> CollectorPayload<[ListeningPort]> {
        let output = CommandRunner.run("/usr/sbin/netstat", arguments: ["-anv"])
        let lines = output.split(separator: "\n")
        var ports: [ListeningPort] = []
        for line in lines where line.contains("LISTEN") {
            let parts = line.split(separator: " ", omittingEmptySubsequences: true)
            if parts.count >= 5 {
                let proto = String(parts[0])
                let addressPort = String(parts[3])
                let components = addressPort.split(separator: ".").map(String.init)
                let port = components.last ?? "?"
                let address = components.dropLast().joined(separator: ".")
                ports.append(ListeningPort(address: address, port: port, protocolType: proto))
            }
        }
        let status = CollectorStatus(state: .ok, errorMessage: ports.isEmpty ? "requires administrator privileges or no ports" : nil)
        return CollectorPayload(status: status, payload: ports)
    }
}

// MARK: Displays Collector
struct DisplaysCollector {
    static func collect() -> CollectorPayload<[DisplayInfo]> {
        var status = CollectorStatus(state: .ok, errorMessage: nil)
        var displayCount: UInt32 = 0
        var activeDisplays = [CGDirectDisplayID](repeating: 0, count: 16)
        let error = CGGetActiveDisplayList(UInt32(activeDisplays.count), &activeDisplays, &displayCount)
        guard error == .success else {
            status = CollectorStatus(state: .failed, errorMessage: "Unable to query displays")
            return CollectorPayload(status: status, payload: nil)
        }
        let displays = activeDisplays.prefix(Int(displayCount)).map { id -> DisplayInfo in
            let width = CGDisplayPixelsWide(id)
            let height = CGDisplayPixelsHigh(id)
            let mode = CGDisplayCopyDisplayMode(id)
            let refresh = mode?.refreshRate
            var scaling: Double? = nil
            if let mode = mode, mode.pixelWidth > 0 {
                scaling = Double(mode.pixelWidth) / Double(mode.width)
            }
            return DisplayInfo(id: id, resolution: "\(width)x\(height)", refreshRate: refresh, scaling: scaling)
        }
        return CollectorPayload(status: status, payload: displays)
    }
}

// MARK: Risk Engine
struct RiskEngine {
    struct Config: Codable {
        var watchlist: [String: [String]] // category : bundleIds/process substrings
        var whitelistPaths: [String]
    }

    static let defaultConfig = Config(
        watchlist: [
            "IDE": ["com.apple.dt.Xcode"],
            "Browser": ["com.google.Chrome", "org.mozilla.firefox"],
            "Chat": ["com.apple.MobileSMS", "com.tinyspeck.slackmacgap", "com.hnc.Discord"],
            "Remote Desktop": ["com.teamviewer.TeamViewer", "com.anydesk.Anydesk"],
            "Screen Recording": ["com.obsproject.obs-studio"],
            "VM": ["com.vmware.fusion", "org.virtualbox.app.VirtualBox"],
            "VPN": ["com.expressvpn.expressvpn"],
            "System": []
        ],
        whitelistPaths: ["/System/Library/", "/System/Applications/"]
    )

    static func evaluate(apps: [RunningApp], processes: [RunningProcess], config: Config = defaultConfig) -> RiskAssessment {
        var reasons: [RiskReason] = []
        var suspiciousApps: [RunningApp] = []
        var suspiciousProcesses: [RunningProcess] = []
        var score = 0

        for app in apps {
            guard let bundleId = app.bundleId else { continue }
            for (category, ids) in config.watchlist {
                if ids.contains(where: { bundleId.contains($0) }) {
                    let reason = RiskReason(category: category, score: 10, message: "Detected app \(bundleId)")
                    reasons.append(reason)
                    suspiciousApps.append(app)
                    score += reason.score
                }
            }
        }

        for process in processes {
            let command = process.command.lowercased()
            let whitelisted = config.whitelistPaths.contains { command.hasPrefix($0.lowercased()) }
            if whitelisted { continue }
            for (category, identifiers) in config.watchlist {
                if identifiers.contains(where: { command.contains($0.lowercased()) }) {
                    let reason = RiskReason(category: category, score: 5, message: "Process \(process.command) matched \(category)")
                    reasons.append(reason)
                    suspiciousProcesses.append(process)
                    score += reason.score
                }
            }
        }

        score = min(score, 100)
        return RiskAssessment(riskScore: score, riskReasons: reasons, suspiciousApps: suspiciousApps, suspiciousProcesses: suspiciousProcesses)
    }
}
