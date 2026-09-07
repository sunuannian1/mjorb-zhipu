import Foundation
import RorkSign

/// 基于 rork-sign（纯 Swift zsign 兼容签名引擎）的 App 签名器。
///
/// 替代 ALTSigner/ldid：
/// - 纯 Swift 流式处理，大 IPA 不会触发 ldid.cpp(538) 内存崩溃；
/// - 自己实现 CMS/PKCS#7 签名，格式与 zsign/codesign 对齐；
/// - inside-out 一次签名主 app、扩展、Framework，并自动嵌入描述文件、生成 CodeResources。
///
/// 本类型只依赖 Foundation + RorkSign（不依赖 AltSign），入参全部是 Sendable 的
/// String/Data，可安全地在后台线程/Task.detached 中执行 CPU 密集型签名。
///
/// P12 解析由调用方（ApplePortalSigningService）用 AltSign 的 ALTCertificate 完成，
/// 因为 AltSign 用 OpenSSL 生成/解析 P12，与 iOS 原生 SecPKCS12Import 和 rork-sign
/// 自带 PKCS12 解析器均不兼容。这里只接收已解析好的 PEM 证书和私钥。
enum RorkAppSigner {

    /// 一个待嵌入的描述文件：bundleID 为改写后的 ID，data 为描述文件原始字节。
    struct ProfileMaterial: Sendable {
        let bundleID: String
        let data: Data
    }

    enum SignError: LocalizedError {
        case missingCertificate
        case missingPrivateKey
        case missingMainProfile(String)
        case identityImportFailed(String)
        case signFailed(String)

        var errorDescription: String? {
            switch self {
            case .missingCertificate:
                return "证书数据缺失，请重新登录 Apple ID 后重试"
            case .missingPrivateKey:
                return "私钥数据缺失，请重新登录 Apple ID 后重试"
            case .missingMainProfile(let bundleID):
                return "主应用描述文件缺失：\(bundleID)"
            case .identityImportFailed(let detail):
                return "证书导入失败：\(detail)"
            case .signFailed(let detail):
                return "签名失败：\(detail)"
            }
        }
    }

    /// 用 rork-sign 原地签名整个 .app bundle。
    ///
    /// 调用前 `SigningWorkspace.prepare` 已完成：解压、改 BundleID、strip arm64e、
    /// 删除旧 _CodeSignature。本方法只负责正式的 CMS 签名（不做 ad-hoc 预处理，
    /// 与 ldid / SideStore 一致，直接对原始 Mach-O 正式签名）。
    /// 可在后台线程执行。
    ///
    /// - Parameters:
    ///   - appURL: .app bundle 路径
    ///   - certificateData: PEM 或 DER 格式证书（由 AltSign ALTCertificate 从 P12 解析）
    ///   - privateKeyData: PEM 或 DER 格式私钥（由 AltSign ALTCertificate 从 P12 解析）
    ///   - mainBundleID: 主应用改写后的 Bundle ID（prepared.mappedMainBundleID）
    ///   - profiles: 全部描述文件（主应用 + 扩展），bundleID 均为改写后的 ID
    ///   - mode: CodeDirectory 哈希模式（影响 CMS 签名中哪种 cdhash 进入签名）
    static func signAppBundle(
        at appURL: URL,
        certificateData: Data,
        privateKeyData: Data,
        mainBundleID: String,
        profiles: [ProfileMaterial],
        appGroupIdentifiers: [String] = [],
        mode: CodeDirectoryHashingMode = .compatible
    ) throws {
        guard certificateData.isEmpty == false else {
            throw SignError.missingCertificate
        }
        guard privateKeyData.isEmpty == false else {
            throw SignError.missingPrivateKey
        }

        // 主描述文件：优先精确匹配主 Bundle ID，兜底取第一个
        guard let mainProfile = profiles.first(where: {
            $0.bundleID.caseInsensitiveCompare(mainBundleID) == .orderedSame
        }) ?? profiles.first else {
            throw SignError.missingMainProfile(mainBundleID)
        }

        // 扩展描述文件：按"改写后的 Bundle ID -> 描述文件数据"建索引
        var extensionProfiles: [String: Data] = [:]
        for profile in profiles {
            if profile.bundleID.caseInsensitiveCompare(mainBundleID) == .orderedSame {
                continue
            }
            extensionProfiles[profile.bundleID] = profile.data
        }

        // rork-sign 接受 PEM 或 DER 格式的证书和私钥，AltSign 解析出的是 PEM
        let identity: SigningIdentity
        do {
            identity = try SigningIdentity(
                certificateData: certificateData,
                privateKeyData: privateKeyData
            )
        } catch {
            throw SignError.identityImportFailed(error.localizedDescription)
        }

        // 主 Bundle ID 已在 prepare 阶段改写，这里传同一个 ID，rork-sign rebase 后保持不变
        let options = AppSigningOptions(
            bundleIdentifier: mainBundleID,
            rootProvisioningProfile: mainProfile.data,
            provisioningProfilesByBundleIdentifier: extensionProfiles,
            appGroupIdentifiers: appGroupIdentifiers,
            embedProvisioningProfiles: true,
            // mode 参数控制 CodeDirectoryHashingMode：
            //   - .compatible：SHA-1 主 CD + SHA-256 备用（老系统兼容）
            //   - .sha256Only：单 SHA-256 主 CD（iOS 18+ 某些场景更稳定）
            codeDirectoryHashingMode: mode
        )

        do {
            try RorkSigner.signBundle(
                at: appURL,
                identity: identity,
                options: options
            )
        } catch {
            throw SignError.signFailed(error.localizedDescription)
        }
    }

    /// 双引擎签名回退：先尝试主模式（compatible），失败后再尝试备用模式（sha256Only）。
    ///
    /// sha256Only 模式仅生成 SHA-256 主 CodeDirectory，iOS 18+ 某些场景下比 dual-CD
    /// 更稳定（尤其是 symtab 规则、SDKVersion 限制较严格的系统）。
    static func signAppBundleWithFallback(
        at appURL: URL,
        certificateData: Data,
        privateKeyData: Data,
        mainBundleID: String,
        profiles: [ProfileMaterial],
        appGroupIdentifiers: [String] = []
    ) throws {
        do {
            try signAppBundle(
                at: appURL,
                certificateData: certificateData,
                privateKeyData: privateKeyData,
                mainBundleID: mainBundleID,
                profiles: profiles,
                appGroupIdentifiers: appGroupIdentifiers,
                mode: .compatible
            )
            NSLog("[Seal] 签名成功（主引擎 .compatible）")
        } catch {
            let primaryError = error
            NSLog("[Seal] 主引擎签名失败（\(primaryError.localizedDescription)），回退到 .sha256Only")

            // 清理可能已写入的 _CodeSignature / Info.plist，避免 rork-sign 二次签名时冲突
            let fm = FileManager.default
            let codesig = appURL.appendingPathComponent("_CodeSignature")
            try? fm.removeItem(at: codesig)

            do {
                try signAppBundle(
                    at: appURL,
                    certificateData: certificateData,
                    privateKeyData: privateKeyData,
                    mainBundleID: mainBundleID,
                    profiles: profiles,
                    appGroupIdentifiers: appGroupIdentifiers,
                    mode: .sha256Only
                )
                NSLog("[Seal] 签名成功（备用引擎 .sha256Only）")
            } catch let fallbackError {
                throw SignError.signFailed(
                    "主引擎：\(primaryError.localizedDescription)；备用引擎：\(fallbackError.localizedDescription)"
                )
            }
        }
    }
}
