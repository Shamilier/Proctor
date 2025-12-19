import Foundation
import CoreGraphics

// MARK: - Base Types

struct CollectorStatus: Codable {
    enum State: String, Codable {
        case ok, partial, failed
    }

    var state: State
    var errorMessage: String?
}

// Wrapper to keep status alongside payload
struct CollectorPayload<T: Codable>: Codable {
    var status: CollectorStatus
    var payload: T?
}

// MARK: - Device Info
struct DeviceInfo: Codable {
    var macOSVersion: String
    var buildVersion: String
    var model: String
    var architecture: String
    var uptime: TimeInterval
    var hostName: String
    var currentUser: String
    var activeUsers: [String]
}

// MARK: - Hardware
struct CPUInfo: Codable {
    var physicalCores: Int
    var logicalCores: Int
    var loadAverage: [Double]
}

struct MemoryInfo: Codable {
    var total: UInt64
    var free: UInt64
    var used: UInt64
}

struct DiskInfo: Codable {
    var total: UInt64
    var free: UInt64
    var mountPoints: [String]
}

struct BatteryInfo: Codable {
    var percentage: Double?
    var isCharging: Bool?
    var cycleCount: Int?
}

struct NetworkInterfaceInfo: Codable, Identifiable {
    var id: String { name }
    var name: String
    var address: String
    var type: String
    var ssid: String?
}

struct HardwareResources: Codable {
    var cpu: CPUInfo
    var memory: MemoryInfo
    var disk: DiskInfo
    var battery: BatteryInfo
    var networkInterfaces: [NetworkInterfaceInfo]
}

// MARK: - Apps & Processes
struct RunningApp: Codable, Identifiable {
    enum Kind: String, Codable { case uiApp, agent }
    var id: Int { pid }
    var name: String
    var bundleId: String?
    var pid: Int
    var path: String?
    var isActive: Bool
    var isHidden: Bool
    var launchDate: Date?
    var kind: Kind
    var teamIdentifier: String?
}

struct RunningProcess: Codable, Identifiable {
    var id: Int { pid }
    var pid: Int
    var command: String
    var arguments: String
    var uid: Int
    var parentPid: Int
}

// MARK: - Permissions
struct PermissionStatus: Codable, Identifiable {
    var id: String { kind }
    var kind: String
    var isAuthorized: Bool
    var explanation: String
    var requestable: Bool
}

// MARK: - Remote Services
struct RemoteServiceStatus: Codable, Identifiable {
    var id: String { name }
    var name: String
    var isEnabled: Bool?
    var note: String?
}

struct ListeningPort: Codable, Identifiable {
    var id: String { "\(protocolType)-\(port)-\(address)" }
    var address: String
    var port: String
    var protocolType: String
}

// MARK: - Displays
struct DisplayInfo: Codable, Identifiable {
    var id: UInt32
    var resolution: String
    var refreshRate: Double?
    var scaling: Double?
}

// MARK: - Risk
struct RiskReason: Codable, Identifiable {
    var id: String { message }
    var category: String
    var score: Int
    var message: String
}

struct RiskAssessment: Codable {
    var riskScore: Int
    var riskReasons: [RiskReason]
    var suspiciousApps: [RunningApp]
    var suspiciousProcesses: [RunningProcess]
}

// MARK: - Timeline
struct TimelineEntry: Codable, Identifiable {
    var id = UUID()
    var timestamp: Date
    var frontmostApp: RunningApp?
    var changedApps: [RunningApp]
}

// MARK: - Report
struct SnapshotReport: Codable {
    var schemaVersion: String
    var generatedAt: Date
    var timeZone: String

    var device: CollectorPayload<DeviceInfo>
    var hardware: CollectorPayload<HardwareResources>
    var runningApps: CollectorPayload<[RunningApp]>
    var runningProcesses: CollectorPayload<[RunningProcess]>
    var permissions: CollectorPayload<[PermissionStatus]>
    var remoteServices: CollectorPayload<[RemoteServiceStatus]>
    var listeningPorts: CollectorPayload<[ListeningPort]>
    var displays: CollectorPayload<[DisplayInfo]>
    var risk: RiskAssessment
    var timeline: [TimelineEntry]?
}
