# System Snapshot & Risk Report (Proctor)

A macOS 13+ SwiftUI menubar-style diagnostics tool that collects a local "system snapshot" and exports a JSON report without using private APIs. The app focuses on transparency, prompts for permissions, and avoids any bypass of macOS security controls.

## Features
- One-click **Scan Now** to collect device info, hardware resources, running apps, processes, permissions, remote services, displays, and open ports.
- **Risk Engine** that scores indicators from a configurable watchlist while respecting a whitelist for system paths.
- Optional **Continuous Monitoring** timeline that records the frontmost app and running apps every 2 seconds (keeps the last 10 minutes and exports JSON Lines).
- **Export Report** to `report.json`, **Copy JSON** to the clipboard, and **Export Timeline** when monitoring is enabled.
- SwiftUI UI with searchable/sortable lists across Overview, Apps, Processes, Permissions, Remote, and Timeline tabs.

## Building & Running
1. Open `Proctor.xcodeproj` in Xcode 15 or newer on macOS 13+.
2. Select the **Proctor** target and run. No code signing or notarization is required for local use.
3. When prompted, grant permissions that you are comfortable with:
   - **Screen Recording**: to check status only.
   - **Accessibility**: for observing window focus changes.
   - **Microphone/Camera**: to query authorization state.

## Data sources & limitations
- Uses public APIs only (`ProcessInfo`, `Host`, `NSWorkspace`, `CGPreflightScreenCaptureAccess`, `AVCaptureDevice`, `IOKit`, `netstat`, `systemsetup`, etc.).
- Some commands (e.g., `netstat`, `kickstart`) may require administrator privileges to return full results; the UI marks these as best-effort instead of failing.
- Input Monitoring status is not available via public API; the UI reflects this limitation.
- Risk scoring relies on a small built-in watchlist and will not block or interfere with any processes.

## Sample report
Run **Scan Now** then **Export Report** to produce a JSON snapshot like `report.sample.json`. The schema includes section status indicators (`ok | partial | failed`) and timestamps with the local time zone.

## Architecture
- **MVVM** with `SnapshotViewModel` driving SwiftUI tabs.
- **Collectors** module isolates data fetching for Device, Hardware, Apps, Processes, Permissions, Remote Services, Ports, Displays.
- **RiskEngine** consumes the snapshot payloads and returns `RiskAssessment` with score, reasons, and suspicious entities.
- **ReportModel** (`SnapshotReport`) is fully `Codable` for export and clipboard copy.
