import Foundation
import UIKit
import ZIPFoundation
@preconcurrency import Minimuxer

@MainActor

/// OTA 本地安装服务（itms-services）：
/// 内嵌 HTTPS 服务器（127.0.0.1）托管签名包与安装清单，
/// 通过 itms-services 协议让 iOS 系统安装器接管安装——
/// 完全绕开 minimuxer/隧道/installd 暂存链路，系统级可靠。
///
/// 一次性引导：首次使用需在「文件 App → Seal」中安装 SealCA.mobileconfig
/// 描述文件，并在 证书信任设置 中开启完全信任（约 30 秒）。
final class OtaInstallService: @unchecked Sendable {
    static let shared = OtaInstallService()

    private var serverPort: UInt16?
    private var identity: (ca: String, cert: String, key: String)?
    private var otaBackgroundTaskID: UIBackgroundTaskIdentifier = .invalid

    private var otaDirectoryURL: URL {
        let dir = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("OTA", isDirectory: true)
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }
    private var identityFileURL: URL {
        otaDirectoryURL.appendingPathComponent("identity.json")
    }
    private var ipaFileURL: URL {
        otaDirectoryURL.appendingPathComponent("app.ipa")
    }
    private var manifestFileURL: URL {
        otaDirectoryURL.appendingPathComponent("manifest.plist")
    }
    private var caProfileFileURL: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("SealCA.mobileconfig")
    }
    /// 用户在文件 App 中可直接点开安装的 CA 描述文件
    var caProfileFileVisibleURL: URL { caProfileFileURL }

    /// 在 Seal 内直接打开 CA 描述文件，系统会自动跳转到设置安装
    func openCAProfileInSettings() {
        guard FileManager.default.fileExists(atPath: caProfileFileURL.path) else { return }
        UIApplication.shared.open(caProfileFileURL)
    }

    /// OTA 安装开关（设置项可覆盖；默认开启）
    var isEnabled: Bool {
        UserDefaults.standard.object(forKey: "SealOTA.enabled") as? Bool ?? true
    }

    // MARK: - 身份证书（生成一次，持久复用）

    private func ensureIdentity() throws {
        if identity != nil { return }
        if let data = try? Data(contentsOf: identityFileURL),
           let obj = try? JSONSerialization.jsonObject(with: data) as? [String: String],
           let ca = obj["ca_pem"], let cert = obj["cert_pem"], let key = obj["key_pem"] {
            identity = (ca, cert, key)
            return
        }

        let json = try Minimuxer.otaIdentityGenerate()
        guard
            let obj = try? JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: String],
            let ca = obj["ca_pem"], let cert = obj["cert_pem"], let key = obj["key_pem"]
        else {
            throw NSError(
                domain: "SealOTA", code: 11,
                userInfo: [NSLocalizedDescriptionKey: "本地证书生成失败"]
            )
        }
        identity = (ca, cert, key)
        try JSONSerialization.data(withJSONObject: obj)
            .write(to: identityFileURL, options: .atomic)
    }

    // MARK: - 描述文件构造

    private func pemBody(_ pem: String) -> Data? {
        let body = pem
            .split(separator: "\n")
            .filter { !$0.contains("-----") }
            .joined()
        return Data(base64Encoded: body)
    }

    private func buildCAProfile() throws -> Data {
        guard let identity else {
            throw NSError(domain: "SealOTA", code: 12)
        }
        guard let der = pemBody(identity.ca) else {
            throw NSError(
                domain: "SealOTA", code: 13,
                userInfo: [NSLocalizedDescriptionKey: "CA 证书解析失败"]
            )
        }
        let payloadUUID = UUID().uuidString
        let profile: [String: Any] = [
            "PayloadContent": [[
                "PayloadContent": der,
                "PayloadDisplayName": "Seal Local Root CA",
                "PayloadIdentifier": "com.mjorb.seal.ota.ca.\(payloadUUID)",
                "PayloadType": "com.apple.security.root",
                "PayloadUUID": payloadUUID,
                "PayloadVersion": 1
            ]],
            "PayloadDisplayName": "Seal 本地安装证书",
            "PayloadIdentifier": "com.mjorb.seal.ota",
            "PayloadType": "Configuration",
            "PayloadUUID": UUID().uuidString,
            "PayloadVersion": 1
        ]
        return try PropertyListSerialization.data(
            fromPropertyList: profile, format: .xml, options: 0
        )
    }

    // MARK: - 服务器

    private func ensureServerRunning() throws {
        if serverPort != nil { return }
        guard let identity else {
            throw NSError(domain: "SealOTA", code: 12)
        }
        // 拼接 fullchain（leaf + CA）— 让 iOS 18+ 能验证完整信任链
        let fullchain = identity.cert + "\n" + identity.ca
        try Minimuxer.otaConfigure(
            caPem: identity.ca,
            certPem: fullchain,
            keyPem: identity.key,
            caProfilePath: caProfileFileURL.path,
            manifestPath: manifestFileURL.path,
            ipaPath: ipaFileURL.path
        )
        serverPort = try Minimuxer.otaServe()
    }

    /// 检查 OTA HTTPS 服务器是否可达（不验证证书信任，只验证服务在响应）
    /// 真正的「系统是否信任 CA」由 itms-services 打开后的系统行为揭示：
    ///   - 信任 → 系统弹窗显示应用信息，用户点安装
    ///   - 不信任 → 静默失败/弹窗报错 → 用户回到 Seal 后触发引导
    private func isOtaServerReachable() async -> Bool {
        guard let port = serverPort else { return false }
        guard let url = URL(string: "https://127.0.0.1:\(port)/ping") else { return false }
        return await withCheckedContinuation { continuation in
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 3
            // 绕过 TLS 证书验证，仅检查服务器是否响应（不验证 CA 信任）
            let session = URLSession(configuration: config, delegate: OtaTrustBypassDelegate(), delegateQueue: nil)
            session.dataTask(with: url) { _, response, _ in
                let ok = (response as? HTTPURLResponse)?.statusCode == 200
                continuation.resume(returning: ok)
                session.finishTasksAndInvalidate()
            }.resume()
        }
    }

    /// 当前活跃的 OTA 服务端口（主服务器优先，备用次之）。
    private var activeServerPort: UInt16? {
        serverPort ?? OtaBackupServer.shared.port
    }

    /// CA 是否已被系统信任（用于前置检查：可跳过直接用 itms 尝试）
    /// 真实反映系统信任状态：URLSession.shared 使用系统证书库
    func isCATrusted() async -> Bool {
        guard let port = activeServerPort else { return false }
        guard let url = URL(string: "https://127.0.0.1:\(port)/ping") else { return false }
        return await withCheckedContinuation { continuation in
            let config = URLSessionConfiguration.ephemeral
            config.timeoutIntervalForRequest = 3
            // 不绕过 cert：让系统自己验证，信任则 ok 否则 err
            URLSession(configuration: config).dataTask(with: url) { _, response, error in
                let ok = error == nil && (response as? HTTPURLResponse)?.statusCode == 200
                continuation.resume(returning: ok)
            }.resume()
        }
    }

    // MARK: - 版本号读取（从签名后 IPA 的 Info.plist）

    private static func readVersion(from ipaData: Data) -> String {
        guard let archive = Archive(data: ipaData, accessMode: .read) else { return "1.0" }
        for entry in archive {
            let path = entry.path
            // 只匹配 Payload/<Name>.app/Info.plist（恰好三段）
            let parts = path.split(separator: "/")
            guard parts.count == 3,
                  parts[0] == "Payload",
                  parts[1].hasSuffix(".app"),
                  parts[2] == "Info.plist"
            else { continue }
            var infoData = Data()
            do {
                _ = try archive.extract(entry) { data in infoData.append(data) }
            } catch { continue }
            guard let info = try? PropertyListSerialization.propertyList(
                from: infoData, format: nil
            ) as? [String: Any],
                  let version = info["CFBundleShortVersionString"] as? String,
                  !version.isEmpty
            else { continue }
            return version
        }
        return "1.0"
    }

    // MARK: - 后台保活（itms-services 触发后系统下载期间保持服务器响应）

    private func keepAliveForOTADownload() {
        if otaBackgroundTaskID != .invalid {
            UIApplication.shared.endBackgroundTask(otaBackgroundTaskID)
            otaBackgroundTaskID = .invalid
        }
        otaBackgroundTaskID = UIApplication.shared.beginBackgroundTask(
            withName: "Seal OTA Install"
        ) { [weak self] in
            guard let self else { return }
            if self.otaBackgroundTaskID != .invalid {
                UIApplication.shared.endBackgroundTask(self.otaBackgroundTaskID)
                self.otaBackgroundTaskID = .invalid
            }
        }
        // 90 秒后自动结束（足够系统下载并安装绝大多数 IPA）
        Task {
            try? await Task.sleep(nanoseconds: 90_000_000_000)
            if self.otaBackgroundTaskID != .invalid {
                await MainActor.run {
                    UIApplication.shared.endBackgroundTask(self.otaBackgroundTaskID)
                    self.otaBackgroundTaskID = .invalid
                }
            }
        }
    }

    // MARK: - 安装入口

    /// 通过 itms-services 触发系统安装。
    /// CA 未就绪时抛出 otaCASetupNeeded（自动把描述文件写入文件 App 并给出指引）。
    /// 主 Rust OTA 失败时，自动回退到 Network.framework 备用服务器并重试一次。
    func installViaOTA(
        ipaData: Data,
        bundleID: String,
        displayName: String,
        version: String
    ) async throws {
        try ensureIdentity()
        try ipaData.write(to: ipaFileURL, options: .atomic)
        try buildCAProfile().write(to: caProfileFileURL, options: .atomic)

        // 主路径：Rust + rustls HTTPS 服务器
        var lastError: Error?
        do {
            try ensureServerRunning()
            guard let port = serverPort else {
                throw NSError(domain: "SealOTA", code: 22,
                    userInfo: [NSLocalizedDescriptionKey: "OTA 本地服务器未就绪"])
            }
            try writeManifest(port: port, bundleID: bundleID, version: Self.readVersion(from: ipaData), displayName: displayName)
            try await openItmsAndKeepAlive(port: port)
            // 主路径已确认接管（itms-services 已拉起系统安装器），释放备用服务器资源
            OtaBackupServer.shared.stop()
            return
        } catch {
            lastError = error
            NSLog("[Seal] OTA 主路径失败：\(error.localizedDescription)，尝试备用 Network.framework HTTPS 服务器")
        }

        // 备用路径仅在主路径非 CA 信任问题时启动（CA 未信任时重试无意义，用户需先完成描述文件安装+信任设置）
        let caUntrusted = (lastError as NSError?)?.isOtaCASetupNeeded ?? false
        if !caUntrusted {
            do {
                serverPort = nil
                let port = try await startBackupServer(bundleID: bundleID, version: Self.readVersion(from: ipaData), displayName: displayName)
                try await openItmsAndKeepAlive(port: port)
                return
            } catch {
                NSLog("[Seal] OTA 备用路径也失败：\(error.localizedDescription)")
            }
        }
        throw lastError ?? NSError(
            domain: "SealOTA", code: 23,
            userInfo: [NSLocalizedDescriptionKey: "OTA 主备服务器均不可用"]
        )
    }

    // MARK: - 主/备 OTA 共用辅助

    private func writeManifest(port: UInt16, bundleID: String, version: String, displayName: String) throws {
        let manifest: [String: Any] = [
            "items": [[
                "assets": [[
                    "kind": "software-package",
                    "url": "https://127.0.0.1:\(port)/app.ipa"
                ]],
                "metadata": [
                    "bundle-identifier": bundleID,
                    "bundle-version": version,
                    "kind": "software",
                    "title": displayName
                ]
            ]]
        ]
        try PropertyListSerialization.data(
            fromPropertyList: manifest, format: .xml, options: 0
        ).write(to: manifestFileURL, options: .atomic)
    }

    /// 检查 CA 信任 → 打开 itms → 后台保活
    private func openItmsAndKeepAlive(port: UInt16) async throws {
        if await isCATrusted() == false {
            // 仅在主服务器路径时走"一次性引导"分支；备用路径已通过不同端口暴露
            throw NSError(
                domain: "SealOTA",
                code: 20,
                userInfo: [
                    NSLocalizedDescriptionKey: "首次 OTA 安装需要信任本地证书（一次性，约 30 秒）",
                    NSLocalizedRecoverySuggestionErrorKey: [
                        "① 打开「文件 App → 我的 iPhone → Seal」→ 点按「SealCA.mobileconfig」→ 安装描述文件",
                        "② 设置 → 通用 → 关于本机 → 证书信任设置 → 开启「Seal Local Root CA」完全信任",
                        "③ 回到 Seal 再点一次安装"
                    ].joined(separator: "\n")
                ]
            )
        }
        let manifestURLString = "https://127.0.0.1:\(port)/manifest.plist"
            .addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? ""
        guard let itms = URL(
            string: "itms-services://?action=download-manifest&url=\(manifestURLString)"
        ) else {
            throw NSError(
                domain: "SealOTA", code: 21,
                userInfo: [NSLocalizedDescriptionKey: "itms-services 地址构造失败"]
            )
        }
        await MainActor.run {
            UIApplication.shared.open(itms)
        }
        keepAliveForOTADownload()
    }

    /// 启动 Network.framework 备用 HTTPS 服务器，返回分配端口。
    private func startBackupServer(bundleID: String, version: String, displayName: String) async throws -> UInt16 {
        guard let identity else {
            throw NSError(domain: "SealOTA", code: 12)
        }
        let caProfile = try buildCAProfile()
        let port = try OtaBackupServer.shared.start(
            caPem: identity.ca,
            leafPem: identity.cert,
            privateKeyPEM: identity.key,
            manifestPath: manifestFileURL.path,
            ipaPath: ipaFileURL.path,
            caProfile: caProfile
        )
        // manifest 已经 writeManifest(port:...) 在 installViaOTA 中按照 port 一致流程写入
        try writeManifest(port: port, bundleID: bundleID, version: version, displayName: displayName)
        return port
    }
}

extension NSError {
    /// 便于上层识别"CA 未就绪"的一次性引导错误
    var isOtaCASetupNeeded: Bool {
        domain == "SealOTA" && code == 20
    }
}

/// URLSession 委托：绕过 TLS 证书链验证（仅用于 isOtaServerReachable 探测服务器是否在线）
/// ⚠️ 不用于实际数据传输！实际安装由 itms-services + 系统级 HTTPS 处理。
private final class OtaTrustBypassDelegate: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?
    ) -> Void) {
        // 对回环地址的任何 server trust 都接受（不验证证书链）
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust {
            if let trust = challenge.protectionSpace.serverTrust {
                completionHandler(.useCredential, URLCredential(trust: trust))
                return
            }
        }
        completionHandler(.performDefaultHandling, nil)
    }
}
