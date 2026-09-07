import Foundation
import UIKit
import ZIPFoundation
@preconcurrency import Minimuxer

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
        try Minimuxer.otaConfigure(
            caPem: identity.ca,
            certPem: identity.cert,
            keyPem: identity.key,
            caProfilePath: caProfileFileURL.path,
            manifestPath: manifestFileURL.path,
            ipaPath: ipaFileURL.path
        )
        serverPort = try Minimuxer.otaServe()
    }

    /// CA 是否已被系统信任（服务器运行中时做 TLS 握手测试）
    func isCATrusted() async -> Bool {
        guard let port = serverPort else { return false }
        return await withCheckedContinuation { continuation in
            var request = URLRequest(url: URL(string: "https://127.0.0.1:\(port)/ping")!)
            request.timeoutInterval = 5
            URLSession.shared.dataTask(with: request) { _, response, error in
                let ok = error == nil
                    && (response as? HTTPURLResponse)?.statusCode == 200
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
    func installViaOTA(
        ipaData: Data,
        bundleID: String,
        displayName: String,
        version: String
    ) async throws {
        try ensureIdentity()
        try ipaData.write(to: ipaFileURL, options: .atomic)

        // 优先从签名后成品包读取真实版本号，外部传入仅作兜底
        let effectiveVersion = Self.readVersion(from: ipaData)

        let manifest: [String: Any] = [
            "items": [[
                "assets": [[
                    "kind": "software-package",
                    "url": "https://127.0.0.1:\(serverPort ?? 8443)/app.ipa"
                ]],
                "metadata": [
                    "bundle-identifier": bundleID,
                    "bundle-version": effectiveVersion,
                    "kind": "software",
                    "title": displayName
                ]
            ]]
        ]
        try PropertyListSerialization.data(
            fromPropertyList: manifest, format: .xml, options: 0
        ).write(to: manifestFileURL, options: .atomic)
        try buildCAProfile().write(to: caProfileFileURL, options: .atomic)

        try ensureServerRunning()

        if await isCATrusted() == false {
            // 引导一次性安装 CA：描述文件已写入文件 App，用户点开安装并信任
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

        let manifestURLString = "https://127.0.0.1:\(serverPort!)/manifest.plist"
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
        // 系统安装器接管后，保持后台任务 90 秒，确保下载期间 HTTPS 服务器不被挂起
        keepAliveForOTADownload()
    }
}

extension NSError {
    /// 便于上层识别“CA 未就绪”的一次性引导错误
    var isOtaCASetupNeeded: Bool {
        domain == "SealOTA" && code == 20
    }
}
