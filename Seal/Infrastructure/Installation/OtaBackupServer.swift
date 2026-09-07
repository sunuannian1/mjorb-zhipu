import Foundation
import Network
import Security

/// 纯 Swift Network.framework HTTPS OTA 备用服务器。
///
/// 当 Rust + rustls OTA 主服务器不可用时（端口占用、TLS provider 加载失败、TLS 握手中途失败），
/// 回退到本实现，在 127.0.0.1 上通过 NWListener + sec_identity 提供相同的 HTTPS 服务：
///   - /manifest.plist
///   - /app.ipa
///   - /SealCA.mobileconfig
///   - /ping
///
/// 身份导入方式：SecCertificateCreateWithData + SecKeyCreateWithData → app 专属 keychain，
/// 再由 SecItemCopyMatching(identifier) 取出 SecIdentity。
final class OtaBackupServer: @unchecked Sendable {
    static let shared = OtaBackupServer()

    private var listener: NWListener?
    private let queue = DispatchQueue(label: "seal.ota.backup.server", qos: .userInitiated)
    private(set) var port: UInt16?

    private var manifestPath: String = ""
    private var ipaPath: String = ""
    private var caProfile: Data = Data()
    private var identityLabel: String?

    private init() {}

    /// 启动备用 HTTPS 服务器。
    /// - Parameters:
    ///   - caPem: CA 证书 PEM（用于信任引导和错误提示；不进入 TLS 握手链，仅记录）
    ///   - leafPem: 叶子证书 PEM（DER）
    ///   - privateKeyPEM: 叶子私钥 PEM（RSA，PKCS#8 或 PKCS#1）
    ///   - manifestPath: manifest.plist 本地路径
    ///   - ipaPath: app.ipa 本地路径
    ///   - caProfile: CA 描述文件内容
    @discardableResult
    func start(
        caPem: String,
        leafPem: String,
        privateKeyPEM: String,
        manifestPath: String,
        ipaPath: String,
        caProfile: Data
    ) throws -> UInt16 {
        if let existing = port { return existing }

        self.manifestPath = manifestPath
        self.ipaPath = ipaPath
        self.caProfile = caProfile

        let label = "com.mjorb.seal.ota.backup.\(UUID().uuidString.prefix(8))"
        let identity = try Self.importIdentity(
            leafPEM: leafPem,
            privateKeyPEM: privateKeyPEM,
            label: label
        )
        self.identityLabel = label

        let tlsOptions = NWProtocolTLS.Options()
        sec_protocol_options_set_local_identity(
            tlsOptions.securityProtocolOptions,
            sec_identity_create(identity)!
        )

        let params = NWParameters(tls: tlsOptions, .tcp)
        params.requiredInterfaceType = .loopback

        let listener = try NWListener(using: params, on: .any)
        self.listener = listener

        let semaphore = DispatchSemaphore(value: 0)
        var startError: Error?
        listener.stateUpdateHandler = { state in
            switch state {
            case .ready:
                if let p = listener.port {
                    self.port = UInt16(p.rawValue)
                }
                semaphore.signal()
            case .failed(let err):
                startError = err
                semaphore.signal()
            case .cancelled:
                semaphore.signal()
            default:
                break
            }
        }

        listener.newConnectionHandler = { [weak self] conn in
            self?.handleConnection(conn)
        }

        listener.start(queue: queue)
        semaphore.wait()

        if let err = startError {
            throw OSError.listenerStartFailed(err.localizedDescription)
        }

        guard let boundPort = port else {
            throw OSError.listenerStartFailed("端口未分配")
        }
        NSLog("[Seal] OTA 备用 HTTPS 服务器已启动，端口：\(boundPort)")
        return boundPort
    }

    func stop() {
        listener?.cancel()
        listener = nil
        port = nil
        if let label = identityLabel {
            let certQuery: [String: Any] = [
                kSecClass as String: kSecClassCertificate,
                kSecAttrLabel as String: label,
            ]
            let keyQuery: [String: Any] = [
                kSecClass as String: kSecClassKey,
                kSecAttrLabel as String: label,
            ]
            SecItemDelete(certQuery as CFDictionary)
            SecItemDelete(keyQuery as CFDictionary)
        }
        identityLabel = nil
    }

    // MARK: - Identity import into current-process keychain

    private static func importIdentity(
        leafPEM: String,
        privateKeyPEM: String,
        label: String
    ) throws -> SecIdentity {
        // 1. 解析 leaf cert DER
        guard let certDER = Self.pemDer(leafPEM) else {
            throw OSError.identityImportFailed("叶子 PEM 无法解析")
        }
        guard let certificate = SecCertificateCreateWithData(nil, certDER as CFData) else {
            throw OSError.identityImportFailed("SecCertificateCreateFromData 失败")
        }

        // 2. 清理本 label 上次残留
        let cleanup: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: label,
        ]
        SecItemDelete(cleanup as CFDictionary)

        // 3. 导入 cert
        var certRef: CFTypeRef?
        let addCert: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecValueRef as String: certificate,
            kSecAttrLabel as String: label,
        ]
        var status = SecItemAdd(addCert as CFDictionary, &certRef)
        guard status == errSecSuccess || status == errSecDuplicateItem else {
            throw OSError.identityImportFailed("导入证书失败：\(status)")
        }

        // 4. 解析 private key DER
        guard let keyDER = Self.pemDer(privateKeyPEM) else {
            throw OSError.identityImportFailed("私钥 PEM 无法解析")
        }

        // 5. 导入 private key（PKCS#8 RSA）
        var keyError: Unmanaged<CFError>?
        let keyDict: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecAttrKeySizeInBits as String: 2048,
        ]
        guard let privateKey = SecKeyCreateWithData(keyDER as CFData, keyDict as CFDictionary, &keyError) else {
            // 再试一次 secitemimport（兼容 PKCS#1 的情况）
            if let err = keyError?.takeRetainedValue() {
                throw OSError.identityImportFailed("SecKeyCreateWithData 失败：\(err)")
            }
            throw OSError.identityImportFailed("私钥导入失败")
        }

        var keyRef: CFTypeRef?
        let addKey: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecValueRef as String: privateKey,
            kSecAttrLabel as String: label,
            kSecAttrApplicationLabel as String: label,
            kSecAttrIsPermanent as String: true,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        status = SecItemAdd(addKey as CFDictionary, &keyRef)
        // 若 key 已存在，继续——不影响 identity 查询
        if status != errSecSuccess && status != errSecDuplicateItem {
            NSLog("[Seal] OTA 备用：私钥导入非致命异常 \(status)")
        }

        // 6. 查找 sec identity（匹配 cert 的 persistent reference）
        let identityQuery: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecAttrLabel as String: label,
            kSecReturnRef as String: true,
        ]
        var identityRef: CFTypeRef?
        status = SecItemCopyMatching(identityQuery as CFDictionary, &identityRef)
        if status == errSecSuccess, let id = identityRef {
            return (id as! SecIdentity)
        }

        // 单 cert + keychain 查询：用 cert persistent ref 找到 identity
        var certPersistRef: CFTypeRef?
        let persistQuery: [String: Any] = [
            kSecClass as String: kSecClassCertificate,
            kSecAttrLabel as String: label,
            kSecReturnPersistentRef as String: true,
        ]
        status = SecItemCopyMatching(persistQuery as CFDictionary, &certPersistRef)
        guard status == errSecSuccess, let persistData = certPersistRef else {
            throw OSError.identityImportFailed("查询 cert persistent ref 失败：\(status)")
        }
        let idQuery: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecValuePersistentRef as String: persistData,
            kSecReturnRef as String: true,
        ]
        status = SecItemCopyMatching(idQuery as CFDictionary, &identityRef)
        guard status == errSecSuccess, let id = identityRef else {
            throw OSError.identityImportFailed("查询 SecIdentity 失败：\(status)")
        }
        return (id as! SecIdentity)
    }

    /// 从 PEM（单段 DER base64）读取为 Data。兼容 "-----BEGIN ...-----" 包装或裸 base64。
    private static func pemDer(_ pem: String) -> Data? {
        // 去掉头尾
        var base64 = pem
            .replacingOccurrences(of: "-----BEGIN [^-]+-----", with: "", options: .regularExpression)
            .replacingOccurrences(of: "-----END [^-]+-----", with: "", options: .regularExpression)
        base64 = base64
            .components(separatedBy: .whitespacesAndNewlines)
            .joined()
        return Data(base64Encoded: base64)
    }

    // MARK: - Connection handling

    private func handleConnection(_ conn: NWConnection) {
        conn.start(queue: queue)
        receive(conn, buffer: Data())
    }

    private func receive(_ conn: NWConnection, buffer: Data) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 16384) { [weak self] data, _, isComplete, err in
            guard let self else { conn.cancel(); return }
            var acc = buffer
            if let data { acc.append(data) }
            if let range = acc.range(of: Data("\r\n\r\n".utf8)) {
                let header = acc.subdata(in: ..<range.lowerBound)
                self.respond(header: header, conn: conn)
                return
            }
            if isComplete || err != nil { conn.cancel(); return }
            self.receive(conn, buffer: acc)
        }
    }

    private func respond(header: Data, conn: NWConnection) {
        guard let s = String(data: header, encoding: .utf8) else { conn.cancel(); return }
        let requestLine = s.split(separator: "\n").first.map(String.init) ?? ""
        let parts = requestLine.split(separator: " ")
        let path = parts.count >= 2 ? String(parts[1].split(separator: "?").first ?? "") : ""

        let (status, contentType, body): (String, String, Data) = {
            switch path {
            case "/manifest.plist":
                return ("200 OK", "application/xml", Self.safeRead(manifestPath))
            case "/app.ipa":
                return ("200 OK", "application/octet-stream", Self.safeRead(ipaPath))
            case "/SealCA.mobileconfig":
                return ("200 OK", "application/x-apple-aspen-config", caProfile)
            case "/ping":
                return ("200 OK", "text/plain", Data("ok".utf8))
            default:
                return ("404 Not Found", "text/plain", Data("not found".utf8))
            }
        }()

        var response = Data()
        response.append(Data("HTTP/1.1 \(status)\r\n".utf8))
        response.append(Data("Content-Type: \(contentType)\r\n".utf8))
        response.append(Data("Content-Length: \(body.count)\r\n".utf8))
        response.append(Data("Connection: close\r\n\r\n".utf8))
        response.append(body)

        conn.send(content: response, completion: .contentProcessed { _ in
            conn.cancel()
        })
    }

    private static func safeRead(_ path: String) -> Data {
        guard FileManager.default.fileExists(atPath: path) else { return Data() }
        return (try? Data(contentsOf: URL(fileURLWithPath: path))) ?? Data()
    }

    // MARK: - Errors

    enum OSError: LocalizedError {
        case invalidArgument(String)
        case identityImportFailed(String)
        case listenerStartFailed(String)

        var errorDescription: String? {
            switch self {
            case .invalidArgument(let m): return m
            case .identityImportFailed(let m): return m
            case .listenerStartFailed(let m): return m
            }
        }
    }
}
