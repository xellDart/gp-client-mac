import SwiftUI
import AppKit
import Security

@main
struct GPClientApp: App {
    var body: some Scene {
        WindowGroup("GlobalProtect") {
            ContentView()
                .frame(width: 340, height: 460)
        }
        .windowResizability(.contentSize)
        .windowStyle(.titleBar)
    }
}

enum ConnectionStatus {
    case disconnected, connecting, connected, error
    var label: String {
        switch self {
        case .disconnected: return "Not Connected"
        case .connecting:   return "Connecting…"
        case .connected:    return "Connected"
        case .error:        return "Connection Failed"
        }
    }
    var color: Color {
        switch self {
        case .connected:    return Color(red: 0.16, green: 0.65, blue: 0.27)
        case .connecting:   return .orange
        case .error:        return .red
        case .disconnected: return Color(white: 0.55)
        }
    }
}

final class VPNController: ObservableObject {
    @Published var portal: String = UserDefaults.standard.string(forKey: "gp.portal") ?? ""
    @Published var username: String = UserDefaults.standard.string(forKey: "gp.username") ?? ""
    @Published var password: String = ""
    @Published var rememberPassword: Bool = UserDefaults.standard.bool(forKey: "gp.rememberPassword")
    @Published var status: ConnectionStatus = .disconnected
    @Published var statusDetail: String = ""
    @Published var assignedIP: String = ""
    @Published var showCredentialSheet: Bool = false
    @Published var showLogSheet: Bool = false
    @Published var showTrustSheet: Bool = false
    @Published var showSetupSheet: Bool = false
    @Published var setupMessage: String = ""
    @Published var pendingPin: String = ""
    @Published var logs: String = ""

    private let keychainService = "com.xelldart.gpclient"

    private let pidFile = "/tmp/gpclient.pid"
    private let dnsCleanupTool = "/usr/local/libexec/gpclient-dns-cleanup"
    private var monitorTimer: Timer?

    private func trustedPinKey() -> String { "gp.cert.\(portal)" }
    private func trustedPin() -> String? {
        UserDefaults.standard.string(forKey: trustedPinKey())
    }

    private func processAlive(_ pid: Int) -> Bool {
        let task = Process()
        task.launchPath = "/bin/ps"
        task.arguments = ["-p", "\(pid)", "-o", "pid="]
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
            let out = String(data: pipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
            return out.trimmingCharacters(in: .whitespacesAndNewlines) == "\(pid)"
        } catch {
            return false
        }
    }

    init() {
        if rememberPassword, !username.isEmpty, !portal.isEmpty {
            if let saved = loadPasswordFromKeychain() {
                self.password = saved
            }
        }
        checkExistingConnection()
        DispatchQueue.global().asyncAfter(deadline: .now() + 0.3) { [weak self] in
            guard let self = self else { return }
            self.runSetupCheck()
            // A previous session may have died (crash, lost network) without
            // running the vpnc-script cleanup, leaving the VPN DNS behind.
            if self.status != .connected { self.restoreDNSIfNeeded() }
        }
    }

    /// Removes DNS/IPv4 state left by vpnc-script when a tunnel died without
    /// running its disconnect cleanup (crash, network loss, forced kill).
    func restoreDNSIfNeeded() {
        guard FileManager.default.fileExists(atPath: dnsCleanupTool) else { return }
        let task = Process()
        task.launchPath = "/usr/bin/sudo"
        var args = ["-n", dnsCleanupTool]
        // Pass the portal so the helper can drop a stale host route to it;
        // only IPv4 literals are accepted (the helper re-validates).
        if portal.range(of: #"^\d{1,3}(\.\d{1,3}){3}$"#, options: .regularExpression) != nil {
            args.append(portal)
        }
        task.arguments = args
        let outPipe = Pipe()
        let errPipe = Pipe()
        task.standardOutput = outPipe
        task.standardError = errPipe
        do {
            try task.run()
        } catch {
            return
        }
        task.waitUntilExit()
        let out = String(data: outPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        if out.contains("cleaned:") {
            let devs = out.replacingOccurrences(of: "cleaned:", with: "")
                .trimmingCharacters(in: .whitespacesAndNewlines)
            appendLog("Restored DNS configuration (stale \(devs)).")
        } else if err.contains("password is required") {
            appendLog("DNS cleanup needs the updated sudoers rules — run Set Up again.")
        }
    }

    func runSetupCheck() {
        let candidates = ["/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect"]
        let openconnect = candidates.first { FileManager.default.isExecutableFile(atPath: $0) }
        if openconnect == nil {
            DispatchQueue.main.async {
                self.setupMessage = "openconnect is not installed.\n\nInstall it first via Homebrew:\n\n    brew install openconnect\n\nThen reopen this app."
                self.showSetupSheet = true
            }
            return
        }
        let task = Process()
        task.launchPath = "/usr/bin/sudo"
        task.arguments = ["-n", openconnect!, "--version"]
        task.standardOutput = Pipe()
        task.standardError = Pipe()
        do {
            try task.run()
            task.waitUntilExit()
            if task.terminationStatus != 0 {
                DispatchQueue.main.async {
                    self.setupMessage = "GlobalProtect needs a one-time setup so it can run openconnect without prompting for your password every connection.\n\nClick Set Up to install a sudoers rule (you will be asked for your Mac password once)."
                    self.showSetupSheet = true
                }
                return
            }
        } catch {
            // ignore
            return
        }
        // Older sudoers installs lack the -INT rule; without it disconnect falls
        // back to SIGTERM and openconnect never restores the system DNS.
        // `sudo -l` is unreliable here: it reports admin-with-password rules as
        // allowed. Executing the marker rule is the only passwordless-proof test.
        let intCheck = Process()
        intCheck.launchPath = "/usr/bin/sudo"
        intCheck.arguments = ["-n", "/usr/bin/true", "gpclient-sudoers-v3"]
        intCheck.standardOutput = Pipe()
        intCheck.standardError = Pipe()
        do {
            try intCheck.run()
            intCheck.waitUntilExit()
            if intCheck.terminationStatus != 0 {
                DispatchQueue.main.async {
                    self.setupMessage = "The installed sudoers rule needs an update so GlobalProtect can shut down cleanly and restore your DNS settings on disconnect.\n\nClick Set Up to update it (you will be asked for your Mac password once)."
                    self.showSetupSheet = true
                }
            }
        } catch {
            // ignore
        }
    }

    func performSetup() {
        let user = NSUserName()
        let candidates = ["/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect"]
        guard let openconnect = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) }) else {
            appendLog("openconnect not found.")
            return
        }
        let sudoersContent = """
        \(user) ALL=(root) NOPASSWD: \(openconnect) *
        \(user) ALL=(root) NOPASSWD: /usr/bin/pkill -INT -F /tmp/gpclient.pid
        \(user) ALL=(root) NOPASSWD: /usr/bin/pkill -F /tmp/gpclient.pid
        \(user) ALL=(root) NOPASSWD: /usr/bin/pkill -KILL -F /tmp/gpclient.pid
        \(user) ALL=(root) NOPASSWD: /usr/bin/pkill -TERM -F /tmp/gpclient.pid
        \(user) ALL=(root) NOPASSWD: \(dnsCleanupTool)
        \(user) ALL=(root) NOPASSWD: /usr/bin/true gpclient-sudoers-v3
        """
        let cleanupScript = """
        #!/bin/sh
        # Remove DNS/IPv4 state left behind by openconnect's vpnc-script when
        # the tunnel died without running its disconnect cleanup. Only touches
        # services whose utun interface no longer exists.
        cleaned=""
        for dev in $(echo "list State:/Network/Service/utun[0-9]*/DNS" | /usr/sbin/scutil | /usr/bin/sed -n 's|.*State:/Network/Service/\\(utun[0-9]*\\)/DNS.*|\\1|p'); do
            if ! /sbin/ifconfig "$dev" >/dev/null 2>&1; then
                printf 'open\\nremove State:/Network/Service/%s/DNS\\nremove State:/Network/Service/%s/IPv4\\nclose\\n' "$dev" "$dev" | /usr/sbin/scutil >/dev/null
                cleaned="$cleaned $dev"
            fi
        done
        # A stale static host route to the VPN portal (added while on a
        # previous network) blocks reconnection with "Can't assign requested
        # address". Accepts the portal as an IPv4-literal argument.
        if [ -n "$1" ]; then
            case "$1" in
                *[!0-9.]*) : ;;
                *)
                    if /usr/sbin/netstat -rn -f inet | /usr/bin/awk '{print $1}' | /usr/bin/grep -qx "$1"; then
                        if /sbin/route -n delete -host "$1" >/dev/null 2>&1; then
                            cleaned="$cleaned route:$1"
                        fi
                    fi
                    ;;
            esac
        fi
        [ -n "$cleaned" ] && echo "cleaned:$cleaned"
        exit 0
        """
        let tmp = NSTemporaryDirectory() + "gpclient-sudoers"
        try? sudoersContent.write(toFile: tmp, atomically: true, encoding: .utf8)
        let tmpScript = NSTemporaryDirectory() + "gpclient-dns-cleanup"
        try? cleanupScript.write(toFile: tmpScript, atomically: true, encoding: .utf8)
        let shellCmd = "/usr/sbin/visudo -cf '\(tmp)' && /bin/mkdir -p /usr/local/libexec && /bin/cp '\(tmpScript)' \(dnsCleanupTool) && /bin/chmod 755 \(dnsCleanupTool) && /usr/sbin/chown root:wheel \(dnsCleanupTool) && /bin/cp '\(tmp)' /etc/sudoers.d/gpclient && /bin/chmod 440 /etc/sudoers.d/gpclient && /usr/sbin/chown root:wheel /etc/sudoers.d/gpclient && /bin/rm '\(tmp)' '\(tmpScript)'"
        let appleScript = "do shell script \(appleScriptString(shellCmd)) with administrator privileges"
        DispatchQueue.global(qos: .userInitiated).async {
            let task = Process()
            task.launchPath = "/usr/bin/osascript"
            task.arguments = ["-e", appleScript]
            let errPipe = Pipe()
            task.standardError = errPipe
            task.standardOutput = Pipe()
            do {
                try task.run()
                task.waitUntilExit()
                if task.terminationStatus == 0 {
                    DispatchQueue.main.async {
                        self.appendLog("Setup completed.")
                        self.showSetupSheet = false
                    }
                } else {
                    let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
                    self.appendLog("Setup failed: \(err)")
                }
            } catch {
                self.appendLog("Setup error: \(error.localizedDescription)")
            }
        }
    }

    private func keychainAccount() -> String { "\(username)@\(portal)" }

    private func savePasswordToKeychain() {
        guard !password.isEmpty else { return }
        let account = keychainAccount()
        let data = Data(password.utf8)
        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: account
        ]
        SecItemDelete(baseQuery as CFDictionary)
        var attrs = baseQuery
        attrs[kSecValueData as String] = data
        attrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlock
        let status = SecItemAdd(attrs as CFDictionary, nil)
        if status != errSecSuccess {
            appendLog("Could not save to Keychain (status \(status)).")
        }
    }

    private func loadPasswordFromKeychain() -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount(),
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess,
              let data = result as? Data,
              let str = String(data: data, encoding: .utf8) else { return nil }
        return str
    }

    private func deletePasswordFromKeychain() {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: keychainService,
            kSecAttrAccount as String: keychainAccount()
        ]
        SecItemDelete(query as CFDictionary)
    }

    func appendLog(_ line: String) {
        DispatchQueue.main.async {
            let ts = DateFormatter.localizedString(from: Date(), dateStyle: .none, timeStyle: .medium)
            self.logs.append("[\(ts)] \(line)\n")
        }
    }

    private func openconnectPath() -> String {
        let candidates = ["/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect"]
        for path in candidates where FileManager.default.fileExists(atPath: path) { return path }
        return "openconnect"
    }

    func requestConnect() {
        guard !portal.isEmpty else {
            statusDetail = "Enter a portal address."
            return
        }
        UserDefaults.standard.set(portal, forKey: "gp.portal")
        if rememberPassword, !username.isEmpty,
           let saved = loadPasswordFromKeychain(), !saved.isEmpty {
            password = saved
            performConnect()
            return
        }
        showCredentialSheet = true
    }

    func performConnect() {
        guard !username.isEmpty, !password.isEmpty else { return }
        UserDefaults.standard.set(username, forKey: "gp.username")
        UserDefaults.standard.set(rememberPassword, forKey: "gp.rememberPassword")
        if rememberPassword {
            savePasswordToKeychain()
        } else {
            deletePasswordFromKeychain()
        }
        showCredentialSheet = false
        status = .connecting
        statusDetail = "Authenticating with \(portal)…"
        appendLog("Connecting to \(portal) as \(username)…")

        let openconnect = openconnectPath()
        let pwd = password
        let user = username
        let host = portal

        try? FileManager.default.removeItem(atPath: pidFile)

        DispatchQueue.global(qos: .userInitiated).async {
            // Clear any stale DNS/route state from a dead tunnel before
            // connecting — a leftover host route to the portal from another
            // network makes the TCP connect fail outright.
            self.restoreDNSIfNeeded()
            var args = ["-n", openconnect,
                        "--protocol=gp",
                        "--user=\(user)",
                        "--passwd-on-stdin",
                        "--background",
                        "--pid-file=\(self.pidFile)",
                        "--syslog"]
            if let pin = self.trustedPin(), !pin.isEmpty {
                args.append("--servercert")
                args.append(pin)
            }
            args.append(host)

            let task = Process()
            task.launchPath = "/usr/bin/sudo"
            task.arguments = args
            let outPipe = Pipe()
            let errPipe = Pipe()
            let inPipe = Pipe()
            task.standardOutput = outPipe
            task.standardError = errPipe
            task.standardInput = inPipe

            // Drain pipes in real time to avoid deadlocks. With --background,
            // openconnect forks a daemon child that inherits stdout/stderr fds;
            // those fds remain open after the parent exits, so a blocking
            // readDataToEndOfFile() would never see EOF.
            let bufferQueue = DispatchQueue(label: "gpclient.pipe-drain")
            var capturedOut = Data()
            var capturedErr = Data()
            outPipe.fileHandleForReading.readabilityHandler = { handle in
                let chunk = handle.availableData
                guard !chunk.isEmpty else { return }
                bufferQueue.sync { capturedOut.append(chunk) }
            }
            errPipe.fileHandleForReading.readabilityHandler = { handle in
                let chunk = handle.availableData
                guard !chunk.isEmpty else { return }
                bufferQueue.sync { capturedErr.append(chunk) }
            }

            do {
                try task.run()
                inPipe.fileHandleForWriting.write(Data(pwd.utf8))
                try? inPipe.fileHandleForWriting.close()
                task.waitUntilExit()
                DispatchQueue.main.async { self.password = "" }

                // Brief settle time for trailing data, then stop draining.
                Thread.sleep(forTimeInterval: 0.1)
                outPipe.fileHandleForReading.readabilityHandler = nil
                errPipe.fileHandleForReading.readabilityHandler = nil
                let combined = bufferQueue.sync {
                    (String(data: capturedOut, encoding: .utf8) ?? "") +
                    (String(data: capturedErr, encoding: .utf8) ?? "")
                }

                if task.terminationStatus != 0 {
                    if combined.contains("a password is required") || combined.contains("sudo: a terminal") {
                        self.appendLog("sudo asked for a password — sudoers rule missing.")
                        DispatchQueue.main.async {
                            self.status = .error
                            self.statusDetail = "Passwordless sudo not configured."
                        }
                        return
                    }
                    self.appendLog("openconnect exited with status \(task.terminationStatus)")
                    self.handleConnectFailure(output: combined)
                    return
                }
                self.waitForPidAndConfirm(capturedOutput: combined)
            } catch {
                self.appendLog("Failed to launch openconnect: \(error.localizedDescription)")
                DispatchQueue.main.async {
                    self.status = .error
                    self.statusDetail = "Could not start openconnect."
                }
            }
        }
    }

    private func shellEscape(_ s: String) -> String {
        return "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    private func appleScriptString(_ s: String) -> String {
        return "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    /// IPv4 address assigned by the VPN: the last utun interface with a
    /// point-to-point ("inet a --> b") address — the tunnel just brought up.
    private func detectAssignedIP() -> String? {
        let task = Process()
        task.launchPath = "/sbin/ifconfig"
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = Pipe()
        do {
            try task.run()
        } catch {
            return nil
        }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        task.waitUntilExit()
        let out = String(data: data, encoding: .utf8) ?? ""
        var currentInterface = ""
        var found: String?
        for line in out.components(separatedBy: "\n") {
            if !line.hasPrefix("\t"), !line.hasPrefix(" "), let name = line.split(separator: ":").first {
                currentInterface = String(name)
            } else if currentInterface.hasPrefix("utun") {
                let parts = line.trimmingCharacters(in: .whitespaces)
                    .components(separatedBy: " ")
                if parts.count >= 2, parts[0] == "inet" {
                    found = parts[1]
                }
            }
        }
        return found
    }

    private func waitForPidAndConfirm(capturedOutput: String) {
        for _ in 0..<40 {
            if let pidStr = try? String(contentsOfFile: pidFile, encoding: .utf8),
               let pid = Int(pidStr.trimmingCharacters(in: .whitespacesAndNewlines)),
               processAlive(pid) {
                self.appendLog("openconnect running (pid \(pid))")
                let ip = self.detectAssignedIP()
                if let ip = ip { self.appendLog("Assigned IP: \(ip)") }
                DispatchQueue.main.async {
                    self.status = .connected
                    self.assignedIP = ip ?? ""
                    self.statusDetail = "Connected to \(self.portal)"
                    self.startMonitor()
                }
                return
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        self.appendLog("openconnect did not start.")
        self.handleConnectFailure(output: capturedOutput)
    }

    private func handleConnectFailure(output: String) {
        if let pin = self.extractPin(from: output) {
            self.appendLog("Server is using a self-signed/unknown certificate.")
            DispatchQueue.main.async {
                self.pendingPin = pin
                self.status = .disconnected
                self.statusDetail = "Untrusted server certificate"
                self.showTrustSheet = true
            }
            return
        }
        let snippet = output
            .components(separatedBy: "\n")
            .filter { !$0.isEmpty }
            .suffix(2)
            .joined(separator: " — ")
        DispatchQueue.main.async {
            self.status = .error
            self.statusDetail = snippet.isEmpty ? "Connection failed." : snippet
        }
    }

    private func extractPin(from log: String) -> String? {
        for line in log.components(separatedBy: "\n") {
            if let range = line.range(of: "pin-sha256:") {
                let rest = line[range.lowerBound...]
                let pin = rest.split(whereSeparator: { $0 == " " || $0 == "\t" || $0 == "\"" || $0 == "'" }).first
                if let pin = pin { return String(pin) }
            }
        }
        return nil
    }

    func trustPendingPin() {
        guard !pendingPin.isEmpty else { return }
        UserDefaults.standard.set(pendingPin, forKey: trustedPinKey())
        appendLog("Trusted server certificate \(pendingPin)")
        pendingPin = ""
        showTrustSheet = false
        showCredentialSheet = true
    }

    func cancelTrust() {
        pendingPin = ""
        showTrustSheet = false
    }

    private func startMonitor() {
        monitorTimer?.invalidate()
        monitorTimer = Timer.scheduledTimer(withTimeInterval: 3.0, repeats: true) { [weak self] _ in
            self?.checkExistingConnection(silent: true)
        }
    }

    private func stopMonitor() {
        monitorTimer?.invalidate()
        monitorTimer = nil
    }

    func checkExistingConnection(silent: Bool = false) {
        if let pidStr = try? String(contentsOfFile: pidFile, encoding: .utf8),
           let pid = Int(pidStr.trimmingCharacters(in: .whitespacesAndNewlines)),
           processAlive(pid) {
            DispatchQueue.main.async {
                if self.status != .connected {
                    let ip = self.detectAssignedIP()
                    self.status = .connected
                    self.assignedIP = ip ?? ""
                    self.statusDetail = "Connected to \(self.portal)"
                    if !silent { self.appendLog("Existing session detected (pid \(pid))") }
                    self.startMonitor()
                }
            }
        } else {
            DispatchQueue.main.async {
                if self.status == .connected {
                    self.appendLog("Connection dropped.")
                    self.status = .disconnected
                    self.statusDetail = ""
                    self.assignedIP = ""
                    self.stopMonitor()
                    // openconnect died without cleanup; drop its stale DNS.
                    DispatchQueue.global(qos: .utility).async {
                        self.restoreDNSIfNeeded()
                    }
                }
            }
        }
    }

    func disconnect() {
        guard let pidStr = try? String(contentsOfFile: pidFile, encoding: .utf8),
              let pid = Int(pidStr.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            status = .disconnected
            statusDetail = ""
            return
        }
        appendLog("Disconnecting (pid \(pid))…")
        statusDetail = "Disconnecting…"
        DispatchQueue.global(qos: .userInitiated).async {
            // SIGINT: openconnect logs off and runs vpnc-script to restore DNS
            // and routes. SIGTERM exits immediately, leaving the VPN DNS behind.
            // The logoff includes a network round-trip to the gateway, so give
            // it up to 10s before escalating.
            let intDelivered = self.runPkill(signal: "-INT")
            var gracefulExit = false
            if intDelivered {
                for _ in 0..<20 {
                    if !self.processAlive(pid) { gracefulExit = true; break }
                    Thread.sleep(forTimeInterval: 0.5)
                }
            }
            if !gracefulExit {
                self.appendLog("openconnect did not respond to SIGINT, sending SIGTERM…")
                self.runPkill(signal: nil)
                Thread.sleep(forTimeInterval: 2.0)
            }
            if self.processAlive(pid) {
                self.appendLog("openconnect did not respond to SIGTERM, sending SIGKILL…")
                self.runPkill(signal: "-KILL")
                Thread.sleep(forTimeInterval: 1.0)
            }
            if self.processAlive(pid) {
                self.appendLog("Failed to kill process \(pid).")
            } else if !gracefulExit {
                self.appendLog("Forced shutdown — cleaning up leftover DNS state…")
                self.restoreDNSIfNeeded()
            }
            DispatchQueue.main.async {
                self.status = .disconnected
                self.statusDetail = ""
                self.assignedIP = ""
                self.stopMonitor()
                self.appendLog("Disconnected.")
            }
        }
    }

    /// Returns false when sudo rejected the command (missing sudoers rule),
    /// so callers can skip the graceful-exit wait.
    @discardableResult
    private func runPkill(signal: String?) -> Bool {
        let task = Process()
        task.launchPath = "/usr/bin/sudo"
        if let sig = signal {
            task.arguments = ["-n", "/usr/bin/pkill", sig, "-F", pidFile]
        } else {
            task.arguments = ["-n", "/usr/bin/pkill", "-F", pidFile]
        }
        let errPipe = Pipe()
        task.standardError = errPipe
        task.standardOutput = Pipe()
        do {
            try task.run()
        } catch {
            return false
        }
        task.waitUntilExit()
        let err = String(data: errPipe.fileHandleForReading.readDataToEndOfFile(), encoding: .utf8) ?? ""
        if err.contains("password is required") || err.contains("sudo:") {
            appendLog("sudo rejected pkill \(signal ?? "") — sudoers rule missing, run Set Up again.")
            return false
        }
        return task.terminationStatus == 0
    }
}

struct ContentView: View {
    @StateObject private var vpn = VPNController()

    var body: some View {
        VStack(spacing: 0) {
            // Header bar
            HStack {
                Image(systemName: "shield.lefthalf.filled")
                    .foregroundColor(Color(red: 0.0, green: 0.42, blue: 0.74))
                Text("GlobalProtect")
                    .font(.system(size: 13, weight: .semibold))
                Spacer()
                Menu {
                    Button("Show Logs…") { vpn.showLogSheet = true }
                    Button("Disconnect", action: vpn.disconnect)
                        .disabled(vpn.status != .connected)
                    Divider()
                    Button("Quit") { NSApp.terminate(nil) }
                } label: {
                    Image(systemName: "line.3.horizontal")
                        .foregroundColor(.secondary)
                }
                .menuStyle(.borderlessButton)
                .frame(width: 28)
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(Color(NSColor.windowBackgroundColor))

            Divider()

            // Main content
            VStack(spacing: 18) {
                Spacer().frame(height: 8)

                ZStack {
                    Circle()
                        .fill(vpn.status.color.opacity(0.12))
                        .frame(width: 110, height: 110)
                    Circle()
                        .stroke(vpn.status.color.opacity(0.35), lineWidth: 2)
                        .frame(width: 110, height: 110)
                    Image(systemName: vpn.status == .connected ? "globe.americas.fill" : "globe.americas")
                        .font(.system(size: 52, weight: .light))
                        .foregroundColor(vpn.status.color)
                }
                .overlay(alignment: .bottomTrailing) {
                    if vpn.status == .connecting {
                        ProgressView()
                            .controlSize(.small)
                            .padding(6)
                            .background(Circle().fill(Color(NSColor.windowBackgroundColor)))
                    }
                }

                VStack(spacing: 4) {
                    Text(vpn.status.label)
                        .font(.system(size: 16, weight: .semibold))
                        .foregroundColor(vpn.status.color)
                    if !vpn.statusDetail.isEmpty {
                        Text(vpn.statusDetail)
                            .font(.system(size: 11))
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 12)
                    }
                    if vpn.status == .connected && !vpn.assignedIP.isEmpty {
                        Text("IP: \(vpn.assignedIP)")
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundColor(.secondary)
                            .textSelection(.enabled)
                            .padding(.vertical, 3)
                            .padding(.horizontal, 8)
                            .background(
                                RoundedRectangle(cornerRadius: 4)
                                    .fill(Color(NSColor.textBackgroundColor))
                            )
                    }
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("Portal")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.secondary)
                    TextField("portal.example.com", text: $vpn.portal)
                        .textFieldStyle(.roundedBorder)
                        .disabled(vpn.status == .connected || vpn.status == .connecting)
                        .autocorrectionDisabled()
                }
                .padding(.horizontal, 24)

                Button(action: {
                    if vpn.status == .connected {
                        vpn.disconnect()
                    } else {
                        vpn.requestConnect()
                    }
                }) {
                    Text(vpn.status == .connected ? "Disconnect" :
                         vpn.status == .connecting ? "Connecting…" : "Connect")
                        .font(.system(size: 13, weight: .semibold))
                        .frame(maxWidth: .infinity)
                        .frame(height: 32)
                        .foregroundColor(.white)
                        .background(
                            RoundedRectangle(cornerRadius: 6)
                                .fill(vpn.status == .connected
                                      ? Color(red: 0.78, green: 0.20, blue: 0.20)
                                      : Color(red: 0.0, green: 0.42, blue: 0.74))
                        )
                }
                .buttonStyle(.plain)
                .disabled(vpn.status == .connecting || vpn.portal.isEmpty)
                .padding(.horizontal, 24)

                Spacer()
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(Color(NSColor.textBackgroundColor))
        }
        .sheet(isPresented: $vpn.showCredentialSheet) {
            CredentialSheet(vpn: vpn)
        }
        .sheet(isPresented: $vpn.showLogSheet) {
            LogSheet(vpn: vpn)
        }
        .sheet(isPresented: $vpn.showTrustSheet) {
            TrustSheet(vpn: vpn)
        }
        .sheet(isPresented: $vpn.showSetupSheet) {
            SetupSheet(vpn: vpn)
        }
    }
}

struct SetupSheet: View {
    @ObservedObject var vpn: VPNController
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "lock.shield")
                    .font(.title)
                    .foregroundColor(Color(red: 0.0, green: 0.42, blue: 0.74))
                Text("First-time setup")
                    .font(.headline)
            }
            Text(vpn.setupMessage)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Skip") { vpn.showSetupSheet = false }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                if vpn.setupMessage.contains("brew install") {
                    Button("OK") { vpn.showSetupSheet = false }
                        .keyboardShortcut(.defaultAction)
                } else {
                    Button("Set Up") { vpn.performSetup() }
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .padding(20)
        .frame(width: 420)
    }
}

struct TrustSheet: View {
    @ObservedObject var vpn: VPNController
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(alignment: .top, spacing: 10) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.title)
                    .foregroundColor(.orange)
                VStack(alignment: .leading, spacing: 4) {
                    Text("Untrusted server certificate")
                        .font(.headline)
                    Text("The portal “\(vpn.portal)” presented a certificate that is not signed by a known authority.")
                        .font(.callout)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            VStack(alignment: .leading, spacing: 4) {
                Text("Fingerprint").font(.caption).foregroundColor(.secondary)
                Text(vpn.pendingPin)
                    .font(.system(.caption, design: .monospaced))
                    .textSelection(.enabled)
                    .padding(8)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .background(Color(NSColor.textBackgroundColor))
                    .cornerRadius(4)
            }
            Text("Only continue if you recognize this server. The fingerprint will be remembered for next time.")
                .font(.caption)
                .foregroundColor(.secondary)
            HStack {
                Button("Cancel") { vpn.cancelTrust() }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Trust & Continue") { vpn.trustPendingPin() }
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding(20)
        .frame(width: 420)
    }
}

struct CredentialSheet: View {
    @ObservedObject var vpn: VPNController
    @FocusState private var focus: Field?
    enum Field { case user, pass }

    var body: some View {
        VStack(spacing: 14) {
            Text("Sign in to \(vpn.portal)")
                .font(.headline)
            VStack(alignment: .leading, spacing: 8) {
                Text("Username").font(.caption).foregroundColor(.secondary)
                TextField("username", text: $vpn.username)
                    .textFieldStyle(.roundedBorder)
                    .focused($focus, equals: .user)
                    .autocorrectionDisabled()
                Text("Password").font(.caption).foregroundColor(.secondary)
                SecureField("password", text: $vpn.password)
                    .textFieldStyle(.roundedBorder)
                    .focused($focus, equals: .pass)
                    .onSubmit { vpn.performConnect() }
                Toggle("Remember password in Keychain", isOn: $vpn.rememberPassword)
                    .font(.caption)
                    .padding(.top, 4)
            }
            HStack {
                Button("Cancel") {
                    vpn.showCredentialSheet = false
                    vpn.password = ""
                }
                .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Sign In") { vpn.performConnect() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(vpn.username.isEmpty || vpn.password.isEmpty)
            }
        }
        .padding(20)
        .frame(width: 320)
        .onAppear { focus = vpn.username.isEmpty ? .user : .pass }
    }
}

struct LogSheet: View {
    @ObservedObject var vpn: VPNController
    var body: some View {
        VStack(spacing: 10) {
            HStack {
                Text("Logs").font(.headline)
                Spacer()
                Button("Clear") { vpn.logs = "" }
                Button("Close") { vpn.showLogSheet = false }
                    .keyboardShortcut(.defaultAction)
            }
            ScrollView {
                Text(vpn.logs.isEmpty ? "No activity yet." : vpn.logs)
                    .font(.system(.caption, design: .monospaced))
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .textSelection(.enabled)
            }
            .frame(width: 480, height: 280)
            .background(Color(NSColor.textBackgroundColor))
            .cornerRadius(6)
        }
        .padding(16)
    }
}
