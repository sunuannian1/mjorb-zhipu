import Foundation
import UIKit
@preconcurrency import AltSign

actor SigningCoordinator {
    private let appStore: any AppStore
    private let accountRepository: any AccountRepository
    private let keychain: KeychainVault
    private let fileStore: AppFileStore
    private let installChannel: any InstallChannel
    private let portal: ApplePortalSigningService

    init(
        appStore: any AppStore,
        accountRepository: any AccountRepository,
        keychain: KeychainVault,
        fileStore: AppFileStore,
        installChannel: any InstallChannel,
        portal: ApplePortalSigningService = ApplePortalSigningService()
    ) {
        self.appStore = appStore
        self.accountRepository = accountRepository
        self.keychain = keychain
        self.fileStore = fileStore
        self.installChannel = installChannel
        self.portal = portal
    }

    func signAndInstall(
        appID: UUID,
        accountID: UUID,
        requestedBundleIdentifier: String? = nil,
        selectedCertificateSerialNumber: String? = nil,
        allowDroppingExtensions: Bool = true,
        installAfterSigning: Bool = true,
        forceResign: Bool = false,
        progress: @Sendable (SigningStage) async -> Void,
        // 证书序列号一旦确定（复用缓存或新申请）即回传，供 UI 显示真实证书，
        // 避免只持有“签名开始时快照”而在失败回看时误显示“证书未准备”。
        onCertificateResolved: @Sendable @escaping (String) async -> Void = { _ in }
    ) async throws -> AppRecord {
        guard var app = try await appStore.fetchAll().first(where: { $0.id == appID }) else {
            throw Self.failure(
                reason: "应用记录不存在",
                recovery: "重新导入 IPA",
                code: "SEAL-SIGN-404"
            )
        }
        guard var account = try await accountRepository.fetchAll().first(where: {
            $0.id == accountID
        }) else {
            throw Self.failure(
                reason: "签名账号记录不存在",
                recovery: "添加 Apple ID",
                code: "SEAL-AUTH-105"
            )
        }
        guard var secret = try await keychain.load(accountID: accountID) else {
            // 不标记 ID 失效：添加后永久保留，只报错提示用户重新验证
            throw Self.failure(
                reason: "本机 Keychain 中缺少当前 Apple ID 的登录凭据。",
                recovery: "重新验证 Apple ID",
                code: "SEAL-AUTH-105a"
            )
        }
        try await validateAccountSession(
            account: account,
            secret: secret,
            selectedAccountID: accountID
        )
        let normalizedSigningMaterial = try await normalizeCachedCertificateState(
            account: account,
            secret: secret
        )
        account = normalizedSigningMaterial.account
        secret = normalizedSigningMaterial.secret
        try SigningCertificateSelectionPolicy.validateAccountAndTeam(
            for: app,
            account: account
        )
        let effectiveCertificateSerialNumber = try SigningCertificateSelectionPolicy
            .resolvedSerialNumber(
                for: app,
                account: account,
                requestedSerialNumber: selectedCertificateSerialNumber
            )
        // 尽早回传实际使用的证书序列号（覆盖复用缓存证书、直接走已签包的路径）。
        if let resolvedCertificateSerialNumber = effectiveCertificateSerialNumber {
            await onCertificateResolved(resolvedCertificateSerialNumber)
        }
        let targetBundleIdentifier = try BundleIDPolicy.targetBundleIdentifier(
            for: app,
            requestedBundleIdentifier: requestedBundleIdentifier
        )
        let workspaceRoot = try await fileStore.signingWorkspace(appID: appID)
        defer { try? FileManager.default.removeItem(at: workspaceRoot) }
        let originalState = app.state
        let originalSecret = secret
        let originalAccount = account
        var didPersistNewSignedArtifact = false

        do {
            try Task.checkCancellation()
            let deviceIdentifier: String
            // 宽松策略：通道暂时不可用时不中止签名，先用配对缓存的 UDID 完成签名，
            // 签名完成后再尝试启动通道安装（签名耗时通常足够 VPN/Minimuxer 恢复）
            var channelReady = false
            if installAfterSigning {
                try await updateState(appID: appID, stage: .waitingForChannel)
                await progress(.waitingForChannel)
                do {
                    deviceIdentifier = try await installChannel.start()
                    channelReady = true
                } catch {
                    if let cached = await installChannel.storedDeviceIdentifier(),
                       cached.isEmpty == false {
                        deviceIdentifier = cached
                    } else {
                        throw Self.failure(
                            reason: "签名前需要先完成一次设备配对，以便按 Apple 官方设备列表生成描述文件。",
                            recovery: "先完成设备配对后重试",
                            code: "SEAL-PAIR-211"
                        )
                    }
                }
            } else if let storedDeviceIdentifier = await installChannel.storedDeviceIdentifier(),
                      storedDeviceIdentifier.isEmpty == false {
                deviceIdentifier = storedDeviceIdentifier
            } else {
                throw Self.failure(
                    reason: "签名前需要先完成一次设备配对，以便按 Apple 官方设备列表生成描述文件。",
                    recovery: "先完成设备配对后重试",
                    code: "SEAL-PAIR-211"
                )
            }

            if installAfterSigning, !forceResign,
               let cachedInstall = try await installCachedSignedIPAIfPossible(
                app: app,
                account: account,
                targetBundleIdentifier: targetBundleIdentifier,
                certificateSerialNumber: effectiveCertificateSerialNumber,
                deviceIdentifier: deviceIdentifier,
                progress: progress
            ) {
                return cachedInstall
            }

            let originalURL = try await fileStore.fileURL(
                relativePath: app.ipaRelativePath
            )
            let preferredIconData: Data?
            if let preferredIconPath = app.preferredIconRelativePath {
                preferredIconData = try? await fileStore.read(relativePath: preferredIconPath)
            } else {
                preferredIconData = nil
            }
            let portalResult = try await portal.sign(
                app: app,
                account: account,
                secret: secret,
                deviceIdentifier: deviceIdentifier,
                originalIPAURL: originalURL,
                workspaceRoot: workspaceRoot,
                targetBundleIdentifier: targetBundleIdentifier,
                preferredIconData: preferredIconData,
                selectedCertificateSerialNumber: effectiveCertificateSerialNumber,
                allowDroppingExtensions: allowDroppingExtensions,
                persistSigningMaterial: { updatedSecret, serialNumber in
                    try await self.persistNewSigningMaterial(
                        updatedSecret,
                        serialNumber: serialNumber,
                        accountID: accountID,
                        originalSecret: originalSecret,
                        originalAccount: originalAccount
                    )
                },
                progress: { stage in
                    await progress(stage)
                }
            )

            account.certificateSerialNumber = portalResult.certificateSerialNumber
            account.selectedCertificateSerialNumber = portalResult.certificateSerialNumber
            account.status = .verified
            account.verificationFailureReason = nil
            account.lastVerifiedAt = Date()
            try await accountRepository.save(account)
            // 新申请证书路径：portal 返回后序列号才最终确定，再回传一次（幂等）。
            await onCertificateResolved(portalResult.certificateSerialNumber)

            let signedPath = try await fileStore.storeSignedIPA(
                sourceURL: portalResult.signedIPAURL,
                appID: appID
            )
            let signedSHA256 = try await fileStore.sha256(relativePath: signedPath)
            applySigningResult(
                portalResult,
                signedPath: signedPath,
                accountID: accountID,
                to: &app
            )
            app.signedIPASHA256 = signedSHA256
            app.signedArtifactStatus = originalState == .installed ? .installed : .available
            app.lastInstallFailureCode = nil
            app.lastInstallFailureReason = nil
            app.state = originalState == .installed ? .installed : .signed
            try await appStore.save(app)
            didPersistNewSignedArtifact = true

            guard installAfterSigning else { return app }

            // 签名时通道若未就绪，安装前再试一次启动（签名期间通道可能已恢复）
            if channelReady == false {
                _ = try? await installChannel.start()
            }

            let installed = try await installSignedIPA(
                app: app,
                signedPath: signedPath,
                bundleIdentifier: portalResult.mappedMainBundleID,
                expirationDate: portalResult.expirationDate,
                progress: progress
            )
            return installed
        } catch is CancellationError {
            if app.signedIPARelativePath != nil, originalState != .installed {
                app.state = .signed
            } else {
                app.state = originalState
            }
            try await persistAppState(app)
            throw CancellationError()
        } catch let failure as ImportFailure {
            // 不标记 ID 失效：添加后永久保留，只报错提示
            if didPersistNewSignedArtifact || failure.code.hasPrefix("SEAL-INSTALL-") {
                app.state = originalState == .installed ? .installed : .signed
                app.signedArtifactStatus = .installFailed
                app.lastInstallFailureCode = failure.code
                app.lastInstallFailureReason = failure.reason
            } else {
                app.state = originalState == .installed ? .installed : originalState
            }
            try await persistAppState(app)
            throw failure
        } catch {
            if didPersistNewSignedArtifact {
                app.state = originalState == .installed ? .installed : .signed
                app.signedArtifactStatus = .installFailed
                app.lastInstallFailureCode = "SEAL-INSTALL-500"
                let nsError = error as NSError
                app.lastInstallFailureReason = "安装流程遇到未预期错误：\(nsError.domain) \(nsError.code) \(nsError.localizedDescription)"
            } else {
                app.state = originalState == .installed ? .installed : originalState
            }
            try await persistAppState(app)
            throw error
        }
    }


    func installSignedArtifact(
        appID: UUID,
        progress: @Sendable (SigningStage) async -> Void
    ) async throws -> AppRecord {
        guard var app = try await appStore.fetchAll().first(where: { $0.id == appID }),
              let signedPath = app.signedIPARelativePath,
              let expectedSHA256 = app.signedIPASHA256,
              let bundleIdentifier = app.mappedBundleIdentifier,
              let expirationDate = app.provisioningProfileExpirationDate else {
            throw Self.failure(
                reason: "本机签名包记录不完整。",
                recovery: "重新签名",
                code: "SEAL-INSTALL-710"
            )
        }
        guard try await fileStore.exists(relativePath: signedPath) else {
            app.signedArtifactStatus = .missing
            try await persistAppState(app)
            throw Self.failure(
                reason: "本机保存的签名包文件缺失。",
                recovery: "重新签名",
                code: "SEAL-INSTALL-711"
            )
        }
        guard try await fileStore.validateSHA256(relativePath: signedPath, expected: expectedSHA256) else {
            app.signedArtifactStatus = .damaged
            try await persistAppState(app)
            throw Self.failure(
                reason: "本机签名包的 SHA-256 校验不一致。",
                recovery: "重新签名",
                code: "SEAL-INSTALL-712"
            )
        }
        guard expirationDate > Date() else {
            app.signedArtifactStatus = .expired
            try await persistAppState(app)
            throw Self.failure(
                reason: "本机签名包的描述文件已经过期。",
                recovery: "重新签名",
                code: "SEAL-INSTALL-713"
            )
        }
        guard BundleIDPolicy.validationError(for: bundleIdentifier) == nil else {
            app.signedArtifactStatus = .damaged
            try await persistAppState(app)
            throw Self.failure(
                reason: "本机签名包的 Bundle ID 记录不完整或格式无效。",
                recovery: "重新签名",
                code: "SEAL-INSTALL-716"
            )
        }

        await progress(.waitingForChannel)
        let currentDeviceIdentifier = try await installChannel.start()
        if let mainTarget = app.signingTargets.first(where: {
            $0.bundleIdentifier.caseInsensitiveCompare(bundleIdentifier) == .orderedSame
        }) {
            guard mainTarget.profileExpirationDate > Date(),
                  mainTarget.deviceIdentifiers.contains(where: {
                      $0.caseInsensitiveCompare(currentDeviceIdentifier) == .orderedSame
                  }) else {
                app.signedArtifactStatus = .deviceUnavailable
                try await persistAppState(app)
                throw Self.failure(
                    reason: "当前设备不在此签名包的描述文件设备列表中，或描述文件已经过期。",
                    recovery: "重新签名",
                    code: "SEAL-INSTALL-714"
                )
            }
            if let signingTeamID = app.signingTeamID,
               mainTarget.teamIdentifier.caseInsensitiveCompare(signingTeamID) != .orderedSame {
                app.signedArtifactStatus = .damaged
                try await persistAppState(app)
                throw Self.failure(
                    reason: "本机签名包的 Team 与保存的签名记录不一致。",
                    recovery: "重新签名",
                    code: "SEAL-INSTALL-717"
                )
            }
            if let serial = app.certificateSerialNumber {
                let expected = serial.filter(\.isHexDigit).uppercased()
                let serials = Set(mainTarget.certificateSerialNumbers.map {
                    $0.filter(\.isHexDigit).uppercased()
                })
                guard serials.contains(expected) else {
                    app.signedArtifactStatus = .damaged
                    try await persistAppState(app)
                    throw Self.failure(
                        reason: "本机签名包的描述文件不包含保存的签名证书。",
                        recovery: "重新签名",
                        code: "SEAL-INSTALL-718"
                    )
                }
            }
        } else if let signedDeviceIdentifier = app.signedDeviceIdentifier,
                  signedDeviceIdentifier.caseInsensitiveCompare(currentDeviceIdentifier) != .orderedSame {
            app.signedArtifactStatus = .deviceUnavailable
            try await persistAppState(app)
            throw Self.failure(
                reason: "当前设备不在此签名包使用的设备记录中。",
                recovery: "重新签名",
                code: "SEAL-INSTALL-714a"
            )
        }

        do {
            return try await installSignedIPA(
                app: app,
                signedPath: signedPath,
                bundleIdentifier: bundleIdentifier,
                expirationDate: expirationDate,
                progress: progress
            )
        } catch let failure as ImportFailure {
            app.state = app.state == .installed ? .installed : .signed
            app.signedArtifactStatus = .installFailed
            app.lastInstallFailureCode = failure.code
            app.lastInstallFailureReason = failure.reason
            try await persistAppState(app)
            throw failure
        } catch {
            app.state = app.state == .installed ? .installed : .signed
            app.signedArtifactStatus = .installFailed
            app.lastInstallFailureCode = "SEAL-INSTALL-500"
            app.lastInstallFailureReason = "安装流程遇到未预期错误，技术信息已写入脱敏日志。"
            try await persistAppState(app)
            throw error
        }
    }

    private func persistNewSigningMaterial(
        _ updatedSecret: AccountSecret,
        serialNumber: String,
        accountID: UUID,
        originalSecret: AccountSecret,
        originalAccount: AppleAccountRecord
    ) async throws {
        do {
            try await keychain.save(updatedSecret, for: accountID)
            guard let reloaded = try await keychain.load(accountID: accountID),
                  reloaded.certificateSerialNumber?.caseInsensitiveCompare(serialNumber) == .orderedSame,
                  let p12 = reloaded.certificateP12,
                  let certificate = try? ALTCertificate(p12Data: p12, password: nil),
                  certificate.serialNumber.caseInsensitiveCompare(serialNumber) == .orderedSame else {
                throw Self.failure(
                    reason: "Apple 返回：无法创建签名证书",
                    recovery: "重试",
                    code: "SEAL-CERT-210"
                )
            }

            var updatedAccount = originalAccount
            updatedAccount.certificateSerialNumber = serialNumber
            updatedAccount.selectedCertificateSerialNumber = serialNumber
            updatedAccount.status = .verified
            updatedAccount.verificationFailureReason = nil
            updatedAccount.lastVerifiedAt = Date()
            try await accountRepository.save(updatedAccount)
        } catch {
            let originalError = error
            var rollbackFailures: [String] = []
            do {
                try await keychain.save(originalSecret, for: accountID)
            } catch {
                rollbackFailures.append("Keychain")
            }
            do {
                try await accountRepository.save(originalAccount)
            } catch {
                rollbackFailures.append("账号记录")
            }
            if rollbackFailures.isEmpty == false {
                throw Self.failure(
                    reason: "证书保存失败，且本地补偿未完整完成（\(rollbackFailures.joined(separator: "、"))）。",
                    recovery: "重新验证 Apple ID 后检查证书状态",
                    code: "SEAL-CERT-215"
                )
            }
            throw originalError
        }
    }

    private func applySigningResult(
        _ result: PortalSigningResult,
        signedPath: String,
        accountID: UUID,
        to app: inout AppRecord
    ) {
        let mainBinding = result.profileBindings[result.mappedMainBundleID]
        app.mappedBundleIdentifier = result.mappedMainBundleID
        app.preferredBundleIdentifier = result.mappedMainBundleID
        app.accountID = accountID
        app.signingTeamID = result.teamID
        app.certificateSerialNumber = result.certificateSerialNumber
        app.signedDeviceIdentifier = result.deviceIdentifier
        app.signedIPARelativePath = signedPath
        app.provisioningProfileUUID = mainBinding?.profileUUID
        app.provisioningProfileName = mainBinding?.profileName
        app.provisioningProfileCreationDate = mainBinding?.creationDate
        app.provisioningProfileExpirationDate = mainBinding?.expirationDate
        app.entitlementValidationStatus = "已按 embedded.mobileprovision 校验"
        app.capabilityValidationStatus = "已按 Apple App ID 与描述文件校验"
        app.lastSignedAt = Date()
        app.removedExtensionBundleIdentifiers = result.droppedExtensionBundleIdentifiers
        app.signingTargets = result.profileBindings.values
            .map(SigningTargetRecord.init(binding:))
            .sorted { $0.bundleIdentifier < $1.bundleIdentifier }

        app.extensions.removeAll {
            result.droppedExtensionBundleIdentifiers.contains(
                $0.originalBundleIdentifier
            )
        }
        for index in app.extensions.indices {
            let mapped = result.mappedBundleIdentifiers[
                app.extensions[index].originalBundleIdentifier
            ]
            app.extensions[index].mappedBundleIdentifier = mapped
            if let mapped, let binding = result.profileBindings[mapped] {
                app.extensions[index].provisioningProfileUUID = binding.profileUUID
                app.extensions[index].provisioningProfileName = binding.profileName
                app.extensions[index].provisioningProfileExpirationDate = binding.expirationDate
                app.extensions[index].certificateSerialNumber = result.certificateSerialNumber
            }
        }
    }

    private func installCachedSignedIPAIfPossible(
        app: AppRecord,
        account: AppleAccountRecord,
        targetBundleIdentifier: String,
        certificateSerialNumber: String?,
        deviceIdentifier: String,
        progress: @Sendable (SigningStage) async -> Void
    ) async throws -> AppRecord? {
        guard let signedPath = app.signedIPARelativePath,
              let expectedSHA256 = app.signedIPASHA256,
              let mappedBundleIdentifier = app.mappedBundleIdentifier,
              mappedBundleIdentifier.caseInsensitiveCompare(targetBundleIdentifier) == .orderedSame,
              app.accountID == account.id,
              app.signingTeamID?.caseInsensitiveCompare(account.teamID) == .orderedSame,
              let storedSerial = app.certificateSerialNumber,
              let certificateSerialNumber,
              storedSerial.caseInsensitiveCompare(certificateSerialNumber) == .orderedSame,
              app.signedDeviceIdentifier?.caseInsensitiveCompare(deviceIdentifier) == .orderedSame,
              let pendingExpiration = app.provisioningProfileExpirationDate,
              pendingExpiration > Date(),
              app.state != .installed || app.expiryDate != pendingExpiration else {
            return nil
        }

        do {
            _ = try await fileStore.fileURL(relativePath: signedPath)
            guard try await fileStore.validateSHA256(
                relativePath: signedPath,
                expected: expectedSHA256
            ) else { return nil }
        } catch {
            return nil
        }
        return try await installSignedIPA(
            app: app,
            signedPath: signedPath,
            bundleIdentifier: mappedBundleIdentifier,
            expirationDate: pendingExpiration,
            progress: progress
        )
    }

    private func installSignedIPA(
        app: AppRecord,
        signedPath: String,
        bundleIdentifier: String,
        expirationDate: Date,
        progress: @Sendable (SigningStage) async -> Void
    ) async throws -> AppRecord {
        var updated = app
        // 安装期间申请后台保活，防止锁屏/切后台时 iOS 挂起网络连接
        let bgTask = await MainActor.run {
            UIApplication.shared.beginBackgroundTask(withName: "Seal IPA Install")
        }
        defer {
            Task { @MainActor in
                UIApplication.shared.endBackgroundTask(bgTask)
            }
        }

        let signedData = try await fileStore.read(relativePath: signedPath)

        // 对齐官方 idevice：安装/校验以「成品包内 Info.plist 的真实 Bundle ID」为准，
        // 外部计算值仅在包内回读失败时回退，消除暂存路径 / ClientOptions / 包内 ID 不一致。
        let effectiveBundleID = SignedArtifactBundleIDReader.bundleIdentifier(in: signedData)
            ?? bundleIdentifier
        // 非标准包上回读值可能与外部计算值不同：以装到设备上的真实 ID 为准回写记录，
        // 否则后续续签用旧计算值做 lookup 会找不到应用，陷入重复签名。
        if effectiveBundleID != bundleIdentifier {
            updated.mappedBundleIdentifier = effectiveBundleID
        }

        // 安装前结构验证：确保签名后 IPA 包含 Payload/*.app、Info.plist、
        // embedded.mobileprovision、主可执行文件，避免把损坏包传到设备端
        // （设备端 installd 对结构损坏的包可能误报 MissingPackagePath 或模糊错误）。
        let validation = SignedArtifactValidator.validate(
            ipaData: signedData,
            expectedBundleID: effectiveBundleID
        )
        guard validation.isValid else {
            let reason = validation.failureReason ?? "签名后 IPA 结构验证未通过"
            let code = validation.failureCode ?? "SEAL-INSTALL-720"
            updated.state = app.state == .installed ? .installed : .signed
            updated.signedArtifactStatus = .installFailed
            updated.lastInstallFailureCode = code
            updated.lastInstallFailureReason = reason
            try await persistAppState(updated)
            throw ImportFailure(
                title: "安装前验证失败",
                reason: reason,
                recovery: "重新签名后再安装",
                code: code
            )
        }

        // OTA 安装（首选）：本地 HTTPS + itms-services，iOS 系统安装器接管。
        // 不依赖配对通道/隧道/installd 暂存链路。Seal 自身更新仍走隧道通道。
        if OtaInstallService.shared.isEnabled && !app.isSeal {
            var otaError: Error?
            do {
                try await updateState(appID: app.id, stage: .pushing)
                await progress(.pushing)
                try await OtaInstallService.shared.installViaOTA(
                    ipaData: signedData,
                    bundleID: effectiveBundleID,
                    displayName: app.displayName,
                    version: "1.0"
                )
                // 系统安装器接管后视为安装完成
                updated.state = .installed
                updated.signedArtifactStatus = .installed
                updated.lastInstallFailureCode = nil
                updated.lastInstallFailureReason = nil
                updated.expiryDate = expirationDate
                updated.lastInstalledAt = Date()
                try await appStore.save(updated)
                return updated
            } catch let caughtOtaError as NSError where caughtOtaError.isOtaCASetupNeeded {
                // 一次性 CA 信任引导：直接呈现给用户，不回退隧道
                updated.signedArtifactStatus = .installFailed
                updated.lastInstallFailureCode = "SEAL-INSTALL-730"
                updated.lastInstallFailureReason = caughtOtaError.localizedDescription
                try await persistAppState(updated)
                throw ImportFailure(
                    title: "需要信任本地证书（一次性）",
                    reason: caughtOtaError.localizedDescription,
                    recovery: "文件 App 安装描述文件 → 证书信任设置开启完全信任 → 回到 Seal 再点安装",
                    code: "SEAL-INSTALL-730"
                )
            } catch {
                otaError = error
                // 不静默回退：记录 OTA 失败原因，告知用户后回退隧道
                NSLog("[Seal] OTA 安装失败，错误：\(error.localizedDescription)，回退到隧道通道")
            }
            // OTA 失败但有明确错误时，保存记录（回退隧道继续尝试 installations）
            if let otaError {
                updated.lastInstallFailureCode = "SEAL-INSTALL-731"
                updated.lastInstallFailureReason = "OTA 不可用：\(otaError.localizedDescription)；正在尝试备选安装…"
                // 不写库（隧道可能成功），仅作为回退时的引导
            }
        }

        if app.isSeal {
            // Persist the real signed-profile expiry before iOS replaces this running app.
            updated.state = .installed
            updated.signedArtifactStatus = .installed
            updated.lastInstallFailureCode = nil
            updated.lastInstallFailureReason = nil
            updated.expiryDate = expirationDate
            updated.lastInstalledAt = Date()
            try await appStore.save(updated)
            try await updateState(appID: app.id, stage: .pushing)
            await progress(.pushing)
            try await installChannel.install(
                ipaData: signedData,
                bundleID: effectiveBundleID,
                isSelfReplacement: true
            )
            updated.hasPendingSelfUpdateSource = false
            try await appStore.save(updated)
            return updated
        }

        do {
            try await updateState(appID: app.id, stage: .pushing)
            await progress(.pushing)
            try await installChannel.install(
                ipaData: signedData,
                bundleID: effectiveBundleID,
                isSelfReplacement: false
            )

            try await updateState(appID: app.id, stage: .verifying)
            await progress(.verifying)
            try await installChannel.verifyInstalled(bundleID: effectiveBundleID)

            updated.state = .installed
            updated.signedArtifactStatus = .installed
            updated.lastInstallFailureCode = nil
            updated.lastInstallFailureReason = nil
            updated.hasPendingSelfUpdateSource = false
            updated.expiryDate = expirationDate
            updated.lastInstalledAt = Date()
            try await appStore.save(updated)
            return updated
        } catch {
            // 安装/验证失败时，应用可能实际已装到设备上（如 installd 后台安装中）。
            // 多次重试查设备状态，已装则静默标记为已安装，不弹失败。
            for _ in 0..<5 {
                try? await Task.sleep(for: .seconds(3))
                let deviceHasApp = (try? await InstalledAppDeviceVerifier.isInstalled(
                    bundleIdentifier: effectiveBundleID
                )) ?? false
                if deviceHasApp {
                    updated.state = .installed
                    updated.signedArtifactStatus = .installed
                    updated.lastInstallFailureCode = nil
                    updated.lastInstallFailureReason = nil
                    updated.hasPendingSelfUpdateSource = false
                    updated.expiryDate = expirationDate
                    updated.lastInstalledAt = Date()
                    try? await appStore.save(updated)
                    return updated
                }
            }
            // 多次查询仍未找到，保留原始错误信息，不要统一报"设备连接断开"。
            // installd 安装失败（签名/描述文件问题）和连接断开是不同原因，
            // 统一提示会误导用户排查方向。
            if let importFailure = error as? ImportFailure {
                throw importFailure
            }
            let nsError = error as NSError
            throw ImportFailure(
                title: "安装失败",
                reason: "安装未完成：\(nsError.localizedDescription)。如桌面已出现云下载图标但点击无法安装，通常是签名或描述文件问题，请检查 Apple ID 证书状态后重试。",
                recovery: "重新安装",
                code: "SEAL-INSTALL-702b"
            )
        }
    }

    private func validateAccountSession(
        account: AppleAccountRecord,
        secret: AccountSecret,
        selectedAccountID: UUID
    ) async throws {
        guard secret.accountIdentifier == account.accountIdentifier else {
            throw Self.failure(
                reason: "本地 Keychain 凭据与当前 Apple ID 记录不一致。",
                recovery: "重新验证 Apple ID",
                code: "SEAL-AUTH-106"
            )
        }

        guard account.teamID.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty == false else {
            throw Self.failure(
                reason: "此 Apple ID 没有可用 Team ID，无法创建 App ID 或证书。",
                recovery: "重新验证 Apple ID",
                code: "SEAL-AUTH-109"
            )
        }
    }

    private func normalizeCachedCertificateState(
        account: AppleAccountRecord,
        secret: AccountSecret
    ) async throws -> (account: AppleAccountRecord, secret: AccountSecret) {
        var updatedAccount = account
        var updatedSecret = secret
        var accountChanged = false

        let localCertificateSerial: String? = {
            guard let p12 = secret.certificateP12,
                  let certificate = try? ALTCertificate(p12Data: p12, password: nil) else {
                return nil
            }
            return certificate.serialNumber
        }()
        let storedSerial = secret.certificateSerialNumber?
            .trimmingCharacters(in: .whitespacesAndNewlines)
        let hasUsableLocalPrivateKey = {
            guard let storedSerial, storedSerial.isEmpty == false,
                  let localCertificateSerial else { return false }
            return storedSerial.caseInsensitiveCompare(localCertificateSerial) == .orderedSame
        }()

        if hasUsableLocalPrivateKey == false,
           secret.certificateSerialNumber != nil || secret.certificateP12 != nil {
            try await keychain.clearSigningMaterial(accountID: account.id)
            updatedSecret.certificateP12 = nil
            updatedSecret.certificateSerialNumber = nil
            updatedSecret.certificateMachineIdentifier = nil
            updatedAccount.certificateSerialNumber = nil
            updatedAccount.selectedCertificateSerialNumber = nil
            accountChanged = true
        } else {
            if updatedAccount.certificateSerialNumber != storedSerial {
                updatedAccount.certificateSerialNumber = storedSerial
                accountChanged = true
            }
            if updatedAccount.selectedCertificateSerialNumber != storedSerial {
                updatedAccount.selectedCertificateSerialNumber = storedSerial
                accountChanged = true
            }
        }

        if accountChanged {
            try await accountRepository.save(updatedAccount)
        }
        return (updatedAccount, updatedSecret)
    }

    private func persistAppState(_ app: AppRecord) async throws {
        do {
            try await appStore.save(app)
        } catch {
            throw Self.failure(
                reason: "签名状态未能写入本机数据库。",
                recovery: "检查本机存储空间后重试",
                code: "SEAL-SIGN-DB-001"
            )
        }
    }

    private func persistAccountState(_ account: AppleAccountRecord) async throws {
        do {
            try await accountRepository.save(account)
        } catch {
            throw Self.failure(
                reason: "Apple ID 状态未能写入本机数据库。",
                recovery: "检查本机存储空间后重试",
                code: "SEAL-AUTH-DB-001"
            )
        }
    }

    private func updateState(appID: UUID, stage: SigningStage) async throws {
        guard var app = try await appStore.fetchAll().first(where: {
            $0.id == appID
        }) else { return }
        app.state = stage.appState
        try await appStore.save(app)
    }

    private static func failure(
        reason: String,
        recovery: String,
        code: String
    ) -> ImportFailure {
        ImportFailure(
            title: "无法完成签名",
            reason: reason,
            recovery: recovery,
            code: code
        )
    }
}

private extension SigningStage {
    var appState: AppState {
        switch self {
        case .waitingForChannel: .waitingForInstallChannel
        case .preparingAccount: .waitingForAccount
        case .preparingCertificate: .preparingCertificate
        case .preparingAppID, .preparingProfiles: .preparingProfiles
        case .signing: .signing
        case .pushing, .installing: .installing
        case .verifying: .verifying
        }
    }
}
