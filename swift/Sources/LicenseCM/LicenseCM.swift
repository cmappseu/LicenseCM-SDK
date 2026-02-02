/**
 * LicenseCM Swift SDK with Enhanced Security Features
 *
 * Supports: iOS 13+, macOS 10.15+, tvOS 13+, watchOS 6+
 */

import Foundation
import CommonCrypto

#if canImport(UIKit)
import UIKit
#endif

#if canImport(AppKit)
import AppKit
#endif

// MARK: - Data Models

public struct ClientData: Codable {
    let hwid: String
    let timestamp: Int64
    let platform: String
    let osVersion: String
    let architecture: String
    let hostname: String
    let swiftVersion: String
    let envIndicators: [String: Bool]
    let vmIndicators: [String]
    let debugIndicators: [String]
}

public struct SessionInfo {
    public let token: String?
    public let expires: Date?
    public let isValid: Bool
}

public struct LicenseResponse: Codable {
    let success: Bool
    let message: String?
    let data: [String: AnyCodable]?
    let securityBlocked: Bool?

    enum CodingKeys: String, CodingKey {
        case success, message, data
        case securityBlocked = "security_blocked"
    }
}

// MARK: - AnyCodable Helper

public struct AnyCodable: Codable {
    public let value: Any

    public init(_ value: Any) {
        self.value = value
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        if container.decodeNil() {
            self.value = NSNull()
        } else if let bool = try? container.decode(Bool.self) {
            self.value = bool
        } else if let int = try? container.decode(Int.self) {
            self.value = int
        } else if let double = try? container.decode(Double.self) {
            self.value = double
        } else if let string = try? container.decode(String.self) {
            self.value = string
        } else if let array = try? container.decode([AnyCodable].self) {
            self.value = array.map { $0.value }
        } else if let dict = try? container.decode([String: AnyCodable].self) {
            self.value = dict.mapValues { $0.value }
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported type")
        }
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()

        switch value {
        case is NSNull:
            try container.encodeNil()
        case let bool as Bool:
            try container.encode(bool)
        case let int as Int:
            try container.encode(int)
        case let double as Double:
            try container.encode(double)
        case let string as String:
            try container.encode(string)
        case let array as [Any]:
            try container.encode(array.map { AnyCodable($0) })
        case let dict as [String: Any]:
            try container.encode(dict.mapValues { AnyCodable($0) })
        default:
            throw EncodingError.invalidValue(value, EncodingError.Context(codingPath: container.codingPath, debugDescription: "Unsupported type"))
        }
    }
}

// MARK: - LicenseCM Client

public class LicenseCMClient {
    private let baseUrl: String
    private let productId: String
    private let secretKey: String

    public var useEncryption: Bool = false
    public var autoHeartbeat: Bool = true
    public var heartbeatInterval: TimeInterval = 300 // 5 minutes

    // Session state
    private var sessionToken: String?
    private var sessionExpires: Date?
    private var heartbeatTimer: Timer?
    private var licenseKey: String?
    private var hwid: String?
    private var publicKey: String?

    // Callbacks
    public var onSessionExpired: (() -> Void)?
    public var onSecurityViolation: (([String: Any]) -> Void)?
    public var onHeartbeatFailed: ((Error) -> Void)?

    private let urlSession: URLSession
    private let decoder = JSONDecoder()
    private let encoder = JSONEncoder()

    public init(baseUrl: String, productId: String, secretKey: String = "") {
        self.baseUrl = baseUrl.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        self.productId = productId
        self.secretKey = secretKey
        self.urlSession = URLSession.shared
    }

    // MARK: - HWID Generation

    public static func generateHwid() -> String {
        var components: [String] = []

        // Platform
        #if os(iOS)
        components.append("iOS")
        #elseif os(macOS)
        components.append("macOS")
        #elseif os(tvOS)
        components.append("tvOS")
        #elseif os(watchOS)
        components.append("watchOS")
        #else
        components.append("unknown")
        #endif

        // Architecture
        #if arch(x86_64)
        components.append("x86_64")
        #elseif arch(arm64)
        components.append("arm64")
        #else
        components.append("unknown")
        #endif

        // Device info
        #if os(iOS)
        components.append(UIDevice.current.name)
        components.append(UIDevice.current.model)
        #elseif os(macOS)
        components.append(Host.current().localizedName ?? "unknown")
        #endif

        // Process info
        components.append(ProcessInfo.processInfo.hostName)
        components.append(String(ProcessInfo.processInfo.processorCount))

        let data = components.joined(separator: "|")
        return sha256(data)
    }

    private static func sha256(_ string: String) -> String {
        let data = Data(string.utf8)
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return hash.map { String(format: "%02x", $0) }.joined()
    }

    private func hmacSha256(_ key: String, _ data: String) -> String {
        let keyData = Data(key.utf8)
        let messageData = Data(data.utf8)

        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))

        keyData.withUnsafeBytes { keyBytes in
            messageData.withUnsafeBytes { messageBytes in
                CCHmac(CCHmacAlgorithm(kCCHmacAlgSHA256),
                       keyBytes.baseAddress, keyData.count,
                       messageBytes.baseAddress, messageData.count,
                       &hash)
            }
        }

        return hash.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: - Client Data Collection

    private func collectClientData() -> ClientData {
        let hwid = self.hwid ?? Self.generateHwid()

        var platform = "unknown"
        var osVersion = "unknown"

        #if os(iOS)
        platform = "iOS"
        osVersion = UIDevice.current.systemVersion
        #elseif os(macOS)
        platform = "macOS"
        osVersion = ProcessInfo.processInfo.operatingSystemVersionString
        #endif

        return ClientData(
            hwid: hwid,
            timestamp: Int64(Date().timeIntervalSince1970 * 1000),
            platform: platform,
            osVersion: osVersion,
            architecture: {
                #if arch(x86_64)
                return "x86_64"
                #elseif arch(arm64)
                return "arm64"
                #else
                return "unknown"
                #endif
            }(),
            hostname: ProcessInfo.processInfo.hostName,
            swiftVersion: "5.9",
            envIndicators: [
                "debug_mode": ProcessInfo.processInfo.environment["DEBUG"] != nil
            ],
            vmIndicators: detectVMIndicators(),
            debugIndicators: detectDebugIndicators()
        )
    }

    private func detectVMIndicators() -> [String] {
        var indicators: [String] = []

        // Check hostname
        let hostname = ProcessInfo.processInfo.hostName.lowercased()
        let vmHostnames = ["vmware", "virtualbox", "sandbox", "virtual", "qemu"]
        for vm in vmHostnames {
            if hostname.contains(vm) {
                indicators.append("suspicious_hostname")
                break
            }
        }

        // Check CPU count
        if ProcessInfo.processInfo.processorCount < 2 {
            indicators.append("single_cpu")
        }

        return indicators
    }

    private func detectDebugIndicators() -> [String] {
        var indicators: [String] = []

        // Check environment variables
        if ProcessInfo.processInfo.environment["DEBUG"] != nil {
            indicators.append("env_debug")
        }

        // Timing analysis
        let start = CFAbsoluteTimeGetCurrent()
        for _ in 0..<1000 {
            _ = Double.random(in: 0...1)
        }
        let duration = (CFAbsoluteTimeGetCurrent() - start) * 1000

        if duration > 100 {
            indicators.append("timing_anomaly")
        }

        return indicators
    }

    // MARK: - Signing

    private func sign(_ data: String) -> String {
        return hmacSha256(secretKey, data)
    }

    // MARK: - Public Key

    public func fetchPublicKey(completion: @escaping (String?) -> Void) {
        let url = URL(string: "\(baseUrl)/api/client/public-key")!

        urlSession.dataTask(with: url) { [weak self] data, response, error in
            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
                  let success = json["success"] as? Bool, success,
                  let dataDict = json["data"] as? [String: Any],
                  let pk = dataDict["public_key"] as? String else {
                completion(nil)
                return
            }

            self?.publicKey = pk
            completion(pk)
        }.resume()
    }

    // MARK: - Initialize

    public func initialize(completion: @escaping (Bool) -> Void) {
        fetchPublicKey { _ in
            completion(true)
        }
    }

    // MARK: - Request

    private func request(
        endpoint: String,
        data: [String: Any],
        completion: @escaping (Result<[String: Any], Error>) -> Void
    ) {
        let clientData = collectClientData()

        var body = data
        body["product_id"] = productId

        if let clientDataEncoded = try? encoder.encode(clientData),
           let clientDataDict = try? JSONSerialization.jsonObject(with: clientDataEncoded) as? [String: Any] {
            body["client_data"] = clientDataDict
        }

        if let token = sessionToken {
            body["session_token"] = token
        }

        let url = URL(string: "\(baseUrl)/api/client\(endpoint)")!
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 30

        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        urlSession.dataTask(with: request) { [weak self] data, response, error in
            if let error = error {
                completion(.failure(error))
                return
            }

            guard let data = data,
                  let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                completion(.failure(NSError(domain: "LicenseCM", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid response"])))
                return
            }

            if let success = json["success"] as? Bool, success {
                let result = json["data"] as? [String: Any] ?? [:]

                // Handle session token rotation
                if let newToken = result["new_token"] as? String {
                    self?.sessionToken = newToken
                }

                // Handle session info
                if let session = result["session"] as? [String: Any] {
                    self?.sessionToken = session["token"] as? String

                    if let expiresAt = session["expires_at"] as? String {
                        let formatter = ISO8601DateFormatter()
                        self?.sessionExpires = formatter.date(from: expiresAt)
                    }
                }

                completion(.success(result))
            } else {
                // Handle security violations
                if let blocked = json["security_blocked"] as? Bool, blocked {
                    self?.onSecurityViolation?([
                        "type": "blocked",
                        "reason": json["message"] as? String ?? "Unknown"
                    ])
                }

                let message = json["message"] as? String ?? "Unknown error"
                completion(.failure(NSError(domain: "LicenseCM", code: -1, userInfo: [NSLocalizedDescriptionKey: message])))
            }
        }.resume()
    }

    // MARK: - License Operations

    public func validate(
        licenseKey: String,
        hwid: String? = nil,
        completion: @escaping (Result<[String: Any], Error>) -> Void
    ) {
        self.licenseKey = licenseKey
        self.hwid = hwid ?? Self.generateHwid()

        request(endpoint: "/validate", data: [
            "license_key": licenseKey,
            "hwid": self.hwid!
        ], completion: completion)
    }

    public func activate(
        licenseKey: String,
        hwid: String? = nil,
        completion: @escaping (Result<[String: Any], Error>) -> Void
    ) {
        self.licenseKey = licenseKey
        self.hwid = hwid ?? Self.generateHwid()

        request(endpoint: "/activate", data: [
            "license_key": licenseKey,
            "hwid": self.hwid!
        ]) { [weak self] result in
            if case .success(let data) = result {
                if self?.autoHeartbeat == true, data["session"] != nil {
                    self?.startHeartbeat()
                }
            }
            completion(result)
        }
    }

    public func deactivate(
        licenseKey: String? = nil,
        hwid: String? = nil,
        completion: @escaping (Result<[String: Any], Error>) -> Void
    ) {
        stopHeartbeat()

        let lk = licenseKey ?? self.licenseKey ?? ""
        let hw = hwid ?? self.hwid ?? Self.generateHwid()

        request(endpoint: "/deactivate", data: [
            "license_key": lk,
            "hwid": hw
        ]) { [weak self] result in
            self?.sessionToken = nil
            self?.sessionExpires = nil
            completion(result)
        }
    }

    public func heartbeat(
        licenseKey: String? = nil,
        hwid: String? = nil,
        completion: @escaping (Result<[String: Any], Error>) -> Void
    ) {
        let lk = licenseKey ?? self.licenseKey ?? ""
        let hw = hwid ?? self.hwid ?? Self.generateHwid()

        request(endpoint: "/heartbeat", data: [
            "license_key": lk,
            "hwid": hw
        ], completion: completion)
    }

    // MARK: - Heartbeat Management

    public func startHeartbeat() {
        stopHeartbeat()

        heartbeatTimer = Timer.scheduledTimer(withTimeInterval: heartbeatInterval, repeats: true) { [weak self] _ in
            self?.heartbeat { result in
                if case .failure(let error) = result {
                    self?.onHeartbeatFailed?(error)

                    let msg = error.localizedDescription.lowercased()
                    if msg.contains("expired") || msg.contains("invalid") {
                        self?.stopHeartbeat()
                        self?.onSessionExpired?()
                    }
                }
            }
        }
    }

    public func stopHeartbeat() {
        heartbeatTimer?.invalidate()
        heartbeatTimer = nil
    }

    // MARK: - Session Info

    public func isSessionValid() -> Bool {
        guard let _ = sessionToken, let expires = sessionExpires else {
            return false
        }
        return Date() < expires
    }

    public func getSessionInfo() -> SessionInfo {
        return SessionInfo(
            token: sessionToken,
            expires: sessionExpires,
            isValid: isSessionValid()
        )
    }

    // MARK: - Cleanup

    public func destroy() {
        stopHeartbeat()
        sessionToken = nil
        sessionExpires = nil
        licenseKey = nil
        hwid = nil
    }
}
