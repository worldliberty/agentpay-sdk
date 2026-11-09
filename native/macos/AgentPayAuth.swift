// AgentPayAuth.swift - `agentpay-auth`, the macOS admin credential helper for AgentPay.
//
// The AgentPay daemon asks the admin to approve sensitive operations by signing a challenge.
// On macOS that admin credential is a P-256 key that lives in the Secure Enclave:
//
// * access control `.privateKeyUsage` + `.userPresence`: every signature needs one system
//   prompt, which accepts Touch ID or the Mac login password;
// * protection `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`: the key never leaves this Mac
//   and is unusable while it is locked;
// * the key is never stored in the keychain (no entitlements needed). Its only persistent form
//   is CryptoKit's `dataRepresentation`, a blob wrapped by the Secure Enclave and useless on
//   any other device, kept in a `0600` JSON key file next to the public key;
// * signatures are `ecdsa-with-SHA256` over the raw message, DER encoded.
//
// The key is reloaded with CryptoKit (`PrivateKey(dataRepresentation:authenticationContext:)`),
// which enforces the key's access control on every signature. Reloading the raw token object
// through `SecKeyCreateWithData` does NOT: such a key signs without any prompt. Never switch the
// reload path away from CryptoKit; `cargo xtask test-macos-auth` guards this property.
//
// Command-line contract: every command prints exactly one JSON object on stdout and exits 0.
// Failures print `{"error":{"code":"<stable code>","message":"..."}}` and exit 1.
//
//   agentpay-auth status
//   agentpay-auth create --key-file <path>
//   agentpay-auth sign --key-file <path> --reason <text> --message-hex <hex> [--no-ui]
//   agentpay-auth delete --key-file <path>
//
// Build with `cargo xtask build-macos-auth`.

import CryptoKit
import CryptoTokenKit
import Darwin
import Foundation
import LocalAuthentication
import Security

// MARK: - Errors

/// Machine-readable failure category. Part of the JSON contract: codes may be added, but
/// existing names must never change.
enum ErrorCode: String, Encodable {
    /// The user, or the system on the user's behalf, dismissed the prompt.
    case userCancel = "user_cancel"
    /// Touch ID or the password was attempted but did not match.
    case authenticationFailed = "authentication_failed"
    /// Too many failed biometric attempts; the user must unlock biometry with the password.
    case biometryLockout = "biometry_lockout"
    /// No fingerprints are enrolled.
    case biometryNotEnrolled = "biometry_not_enrolled"
    /// The Mac has no login password, so user presence cannot be verified.
    case passcodeNotSet = "passcode_not_set"
    /// No GUI session can show the prompt (SSH, daemons) or `--no-ui` was requested.
    case interactionNotAllowed = "interaction_not_allowed"
    /// The key can no longer be used, or the key file does not match the Secure Enclave key.
    case keyInvalidated = "key_invalidated"
    /// The key file does not exist.
    case keyNotFound = "key_not_found"
    /// The request or the key file was malformed or unsafe to use.
    case invalidInput = "invalid_input"
    /// This Mac has no usable Secure Enclave.
    case secureEnclaveUnavailable = "secure_enclave_unavailable"
    /// Anything else; see the message.
    case other
}

/// An error with a stable code and a diagnostic message (the message is not part of the
/// contract).
struct AuthError: Error {
    let code: ErrorCode
    let message: String

    static func invalidInput(_ message: String) -> AuthError {
        AuthError(code: .invalidInput, message: message)
    }

    /// Wraps a failed POSIX call, reading `errno` at the call site.
    static func posix(_ context: String, errno code: Int32 = errno) -> AuthError {
        AuthError(code: .other, message: "\(context): \(String(cString: strerror(code)))")
    }
}

/// Maps errors from LocalAuthentication, Security, CryptoTokenKit and CryptoKit onto
/// `ErrorCode`s.
enum ErrorClassifier {
    /// Bound on how many `NSUnderlyingError` levels are inspected.
    static let maxChainDepth = 8

    /// Builds an `AuthError` for `error`, falling back to `fallback` when no error in the chain
    /// carries a specific meaning.
    static func authError(_ context: String, _ error: Error, fallback: ErrorCode) -> AuthError {
        if let error = error as? AuthError { return error }
        let chain = underlyingChain(of: error)
        let trail = chain.map { "\($0.domain) \($0.code)" }.joined(separator: " <- ")
        let description = chain.first?.localizedDescription ?? String(describing: error)
        return AuthError(
            code: classify(chain: chain) ?? fallback,
            message: "\(context): \(description) [\(trail)]")
    }

    /// LocalAuthentication knows best what happened at the prompt, so its errors win over the
    /// Security/CryptoTokenKit wrappers anywhere in the chain; otherwise the first recognized
    /// error wins.
    static func classify(chain: [NSError]) -> ErrorCode? {
        let fromLocalAuthentication = chain.lazy
            .filter { $0.domain == LAErrorDomain }
            .compactMap(classify)
            .first
        return fromLocalAuthentication ?? chain.lazy.compactMap(classify).first
    }

    /// Classifies a single error, or returns `nil` when it carries no specific meaning.
    static func classify(_ error: NSError) -> ErrorCode? {
        switch error.domain {
        case LAErrorDomain:
            guard let code = LAError.Code(rawValue: error.code) else { return nil }
            switch code {
            case .userCancel, .userFallback, .systemCancel, .appCancel: return .userCancel
            case .authenticationFailed: return .authenticationFailed
            case .biometryLockout: return .biometryLockout
            case .biometryNotEnrolled: return .biometryNotEnrolled
            case .passcodeNotSet: return .passcodeNotSet
            case .notInteractive: return .interactionNotAllowed
            default: return nil
            }
        case NSOSStatusErrorDomain:
            switch OSStatus(truncatingIfNeeded: error.code) {
            case errSecUserCanceled: return .userCancel
            case errSecAuthFailed: return .authenticationFailed
            case errSecInteractionNotAllowed: return .interactionNotAllowed
            case errSecItemNotFound: return .keyInvalidated
            default: return nil
            }
        case TKError.errorDomain:
            guard let code = TKError.Code(rawValue: error.code) else { return nil }
            switch code {
            case .corruptedData, .objectNotFound, .tokenNotFound: return .keyInvalidated
            case .canceledByUser: return .userCancel
            case .authenticationFailed: return .authenticationFailed
            case .authenticationNeeded: return .interactionNotAllowed
            default: return nil
            }
        default:
            return nil
        }
    }

    /// The error followed by its `NSUnderlyingErrorKey` chain, outermost first.
    static func underlyingChain(of error: Error) -> [NSError] {
        var chain: [NSError] = []
        var current: NSError? = error as NSError
        while let next = current, chain.count < maxChainDepth {
            chain.append(next)
            current = next.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        return chain
    }
}

// MARK: - Input validation

enum Validation {
    /// Longest accepted prompt reason, in Unicode scalars.
    static let maxReasonScalars = 200
    /// Largest accepted message to sign, in bytes. Daemon challenges are far smaller.
    static let maxMessageBytes = 16 * 1024

    /// macOS renders the prompt as "<app> is trying to <reason>.", so the reason must be a
    /// single, visibly honest line: control, format (e.g. bidi overrides) and line-separator
    /// characters are rejected.
    static func checkReason(_ reason: String) throws {
        if reason.trimmingCharacters(in: .whitespaces).isEmpty {
            throw AuthError.invalidInput("--reason must name the operation being approved")
        }
        if reason.unicodeScalars.count > maxReasonScalars {
            throw AuthError.invalidInput("--reason must be at most \(maxReasonScalars) characters")
        }
        let forbidden: Set<Unicode.GeneralCategory> = [
            .control, .format, .lineSeparator, .paragraphSeparator,
        ]
        if reason.unicodeScalars.contains(where: { forbidden.contains($0.properties.generalCategory) }) {
            throw AuthError.invalidInput("--reason must not contain control or format characters")
        }
    }

    /// Decodes `--message-hex` (an optional `0x` prefix is accepted) and checks its size.
    static func message(fromHex text: String) throws -> Data {
        let digits = text.hasPrefix("0x") ? String(text.dropFirst(2)) : text
        if digits.utf8.count > 2 * maxMessageBytes {
            throw AuthError.invalidInput("message must be at most \(maxMessageBytes) bytes")
        }
        guard let message = Hex.decode(digits) else {
            throw AuthError.invalidInput("--message-hex is not valid hex")
        }
        if message.isEmpty {
            throw AuthError.invalidInput("message must not be empty")
        }
        return message
    }
}

enum Hex {
    static func encode(_ data: Data) -> String {
        let digits = Array("0123456789abcdef".utf8)
        var out: [UInt8] = []
        out.reserveCapacity(data.count * 2)
        for byte in data {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0f)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Decodes an even-length hex string (either case); `nil` if it is not valid hex.
    static func decode(_ text: String) -> Data? {
        let bytes = Array(text.utf8)
        guard bytes.count.isMultiple(of: 2) else { return nil }
        var out = Data(capacity: bytes.count / 2)
        var index = 0
        while index < bytes.count {
            guard let high = nibble(bytes[index]), let low = nibble(bytes[index + 1]) else {
                return nil
            }
            out.append(high << 4 | low)
            index += 2
        }
        return out
    }

    private static func nibble(_ character: UInt8) -> UInt8? {
        switch character {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return character - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return character - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return character - UInt8(ascii: "A") + 10
        default: return nil
        }
    }
}

// MARK: - Key file

/// On-disk form of the admin key.
struct KeyFileContents: Codable {
    let kind: String
    let version: Int
    /// Uncompressed SEC1 (x9.63) public key: `04 || X || Y`.
    let publicKeySec1Hex: String
    /// CryptoKit `dataRepresentation`: the Secure Enclave-wrapped private key.
    let dataRepresentationHex: String
}

/// A validated key file.
struct StoredKey {
    let publicKey: P256.Signing.PublicKey
    let publicKeySec1: Data
    let dataRepresentation: Data
}

/// Reads, writes and removes key files. Symlinks are refused everywhere, new files are created
/// atomically with mode `0600`, and existing files are never overwritten.
enum KeyFileStore {
    static let kind = "agentpay-admin-key"
    static let version = 1
    /// Upper bound on key file size; real files are well under 1 KiB.
    static let maxBytes = 64 * 1024
    private static let fieldNames: Set<String> = [
        "kind", "version", "publicKeySec1Hex", "dataRepresentationHex",
    ]
    private static let groupOrOtherWritable: mode_t = 0o022

    /// Checks that a new key file can be created at `path`, before any key is generated.
    static func checkCreatable(_ path: String) throws {
        _ = try fileName(of: path)
        try ensureAbsent(path)
        try checkParentDirectory(of: path)
    }

    /// Atomically creates `path` with `contents` and mode `0600`. Fails if `path` exists.
    static func writeNew(_ path: String, contents: Data) throws {
        try checkCreatable(path)
        let directory = parentDirectory(of: path)
        let nonce = Hex.encode(withUnsafeBytes(of: UInt64.random(in: .min ... .max)) { Data($0) })
        let tempPath = "\(directory)/.\(try fileName(of: path)).\(getpid()).\(nonce).tmp"

        let fd = open(tempPath, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0o600)
        guard fd >= 0 else { throw AuthError.posix("failed to create \(tempPath)") }
        var renamed = false
        // The temp file holds key material and must not linger on failure.
        defer { if !renamed { unlink(tempPath) } }
        do {
            defer { close(fd) }
            guard fchmod(fd, 0o600) == 0 else { throw AuthError.posix("failed to chmod \(tempPath)") }
            try writeAll(fd, contents, path: tempPath)
            // F_FULLFSYNC flushes the drive cache too; fall back to fsync where unsupported.
            guard fcntl(fd, F_FULLFSYNC) == 0 || fsync(fd) == 0 else {
                throw AuthError.posix("failed to sync \(tempPath)")
            }
        }
        // RENAME_EXCL makes "never overwrite" atomic even against a racing writer.
        guard renamex_np(tempPath, path, UInt32(RENAME_EXCL)) == 0 else {
            let code = errno
            if code == EEXIST {
                throw AuthError.invalidInput("\(path) already exists; delete the existing key first")
            }
            throw AuthError.posix("failed to move the key file into \(path)", errno: code)
        }
        renamed = true
        syncDirectory(directory)
    }

    /// Reads and validates a key file, refusing symlinks, non-regular files, files owned by
    /// another user, and files writable by group or others.
    static func read(_ path: String) throws -> StoredKey {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)
        guard fd >= 0 else {
            let code = errno
            switch code {
            case ENOENT:
                throw AuthError(code: .keyNotFound, message: "key file \(path) does not exist")
            case ELOOP:
                throw AuthError.invalidInput("\(path) is a symlink; refusing to follow it")
            default:
                throw AuthError.posix("failed to open \(path)", errno: code)
            }
        }
        defer { close(fd) }

        var info = stat()
        guard fstat(fd, &info) == 0 else { throw AuthError.posix("failed to stat \(path)") }
        guard info.st_mode & S_IFMT == S_IFREG else {
            throw AuthError.invalidInput("\(path) is not a regular file")
        }
        guard info.st_uid == geteuid() else {
            throw AuthError.invalidInput("\(path) is not owned by the current user")
        }
        guard info.st_mode & groupOrOtherWritable == 0 else {
            throw AuthError.invalidInput("\(path) is writable by group or others; expected mode 0600")
        }
        guard info.st_size <= maxBytes else { throw AuthError.invalidInput("\(path) is too large") }
        return try parse(readAll(fd, path: path), path: path)
    }

    /// Deletes a key file after checking that it is one. The Secure Enclave blob is useless
    /// without the file, so this destroys the admin key.
    static func remove(_ path: String) throws {
        var info = stat()
        if lstat(path, &info) != 0 {
            let code = errno
            if code == ENOENT {
                throw AuthError(code: .keyNotFound, message: "key file \(path) does not exist")
            }
            throw AuthError.posix("failed to stat \(path)", errno: code)
        }
        if info.st_mode & S_IFMT == S_IFLNK {
            throw AuthError.invalidInput("\(path) is a symlink; refusing to delete through it")
        }
        _ = try read(path)
        guard unlink(path) == 0 else { throw AuthError.posix("failed to delete \(path)") }
        syncDirectory(parentDirectory(of: path))
    }

    /// Encodes a new key file.
    static func encode(publicKeySec1: Data, dataRepresentation: Data) throws -> Data {
        let contents = KeyFileContents(
            kind: kind,
            version: version,
            publicKeySec1Hex: Hex.encode(publicKeySec1),
            dataRepresentationHex: Hex.encode(dataRepresentation))
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return try encoder.encode(contents) + Data("\n".utf8)
    }

    static func parse(_ data: Data, path: String) throws -> StoredKey {
        let malformed = AuthError.invalidInput("\(path) is not a valid AgentPay admin key file")
        guard let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
            Set(object.keys) == fieldNames,
            let contents = try? JSONDecoder().decode(KeyFileContents.self, from: data)
        else { throw malformed }
        guard contents.kind == kind else {
            throw AuthError.invalidInput("\(path) is not an AgentPay admin key file (kind \(contents.kind))")
        }
        guard contents.version == version else {
            throw AuthError.invalidInput("\(path) has unsupported key file version \(contents.version)")
        }
        guard let publicKeySec1 = Hex.decode(contents.publicKeySec1Hex),
            publicKeySec1.count == 65, publicKeySec1.first == 0x04,
            let publicKey = try? P256.Signing.PublicKey(x963Representation: publicKeySec1)
        else {
            throw AuthError.invalidInput("\(path) does not hold an uncompressed P-256 public key")
        }
        guard let blob = Hex.decode(contents.dataRepresentationHex), !blob.isEmpty else {
            throw AuthError.invalidInput("\(path) does not hold a Secure Enclave key blob")
        }
        return StoredKey(publicKey: publicKey, publicKeySec1: publicKeySec1, dataRepresentation: blob)
    }

    // MARK: Filesystem helpers

    private static func fileName(of path: String) throws -> String {
        let name = (path as NSString).lastPathComponent
        guard !path.hasSuffix("/"), !name.isEmpty, name != ".", name != ".." else {
            throw AuthError.invalidInput("--key-file must name a file")
        }
        return name
    }

    private static func parentDirectory(of path: String) -> String {
        let parent = (path as NSString).deletingLastPathComponent
        return parent.isEmpty ? "." : parent
    }

    private static func ensureAbsent(_ path: String) throws {
        var info = stat()
        if lstat(path, &info) == 0 {
            if info.st_mode & S_IFMT == S_IFLNK {
                throw AuthError.invalidInput("\(path) is a symlink; refusing to write through it")
            }
            throw AuthError.invalidInput("\(path) already exists; delete the existing key first")
        }
        let code = errno
        if code != ENOENT { throw AuthError.posix("failed to stat \(path)", errno: code) }
    }

    /// The directory must exist, belong to the current user (or root), and not be writable
    /// by group or others, so nobody else can swap the key file.
    private static func checkParentDirectory(of path: String) throws {
        let directory = parentDirectory(of: path)
        var info = stat()
        guard stat(directory, &info) == 0 else {
            let code = errno
            if code == ENOENT { throw AuthError.invalidInput("directory \(directory) does not exist") }
            throw AuthError.posix("failed to stat \(directory)", errno: code)
        }
        guard info.st_mode & S_IFMT == S_IFDIR else {
            throw AuthError.invalidInput("\(directory) is not a directory")
        }
        guard info.st_uid == geteuid() || info.st_uid == 0 else {
            throw AuthError.invalidInput("directory \(directory) is not owned by the current user")
        }
        guard info.st_mode & groupOrOtherWritable == 0 else {
            throw AuthError.invalidInput("directory \(directory) is writable by group or others")
        }
    }

    private static func writeAll(_ fd: Int32, _ data: Data, path: String) throws {
        try data.withUnsafeBytes { buffer in
            var offset = 0
            while offset < buffer.count {
                let written = Darwin.write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                if written < 0 {
                    if errno == EINTR { continue }
                    throw AuthError.posix("failed to write \(path)")
                }
                offset += written
            }
        }
    }

    private static func readAll(_ fd: Int32, path: String) throws -> Data {
        var result = Data()
        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = buffer.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress, $0.count) }
            if count < 0 {
                if errno == EINTR { continue }
                throw AuthError.posix("failed to read \(path)")
            }
            if count == 0 { return result }
            result.append(contentsOf: buffer[..<count])
            if result.count > maxBytes { throw AuthError.invalidInput("\(path) is too large") }
        }
    }

    /// Persists a rename or unlink. Failure is not fatal: some filesystems refuse it.
    private static func syncDirectory(_ directory: String) {
        let fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { return }
        _ = fsync(fd)
        close(fd)
    }
}

// MARK: - Commands

struct StatusOutput: Encodable {
    struct Biometry: Encodable {
        /// Whether a biometric prompt can be evaluated right now.
        let available: Bool
        /// `touch_id`, `face_id` or `none`.
        let kind: String
    }

    let secureEnclaveAvailable: Bool
    let biometry: Biometry
    /// Whether the user-presence policy (biometry or the login password) can be evaluated.
    let userPresenceAvailable: Bool
}

struct CreateOutput: Encodable {
    let publicKeySec1Hex: String
}

struct SignOutput: Encodable {
    let signatureDerHex: String
}

struct DeleteOutput: Encodable {
    let deleted: Bool
}

enum Commands {
    /// Reports Secure Enclave, biometry and user-presence availability. Never prompts.
    static func status() -> StatusOutput {
        let biometricContext = LAContext()
        let biometryAvailable = biometricContext.canEvaluatePolicy(
            .deviceOwnerAuthenticationWithBiometrics, error: nil)
        // `biometryType` is only meaningful after `canEvaluatePolicy` ran on the context.
        let kind: String
        switch biometricContext.biometryType {
        case .touchID: kind = "touch_id"
        case .faceID: kind = "face_id"
        default: kind = "none"
        }
        return StatusOutput(
            secureEnclaveAvailable: SecureEnclave.isAvailable,
            biometry: .init(available: biometryAvailable, kind: kind),
            userPresenceAvailable: LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: nil))
    }

    /// Creates a new Secure Enclave key and writes it to `keyFile`. Never prompts.
    ///
    /// `requireUserPresence` is only turned off by automated tests, which have no human to
    /// answer the prompt.
    static func create(keyFile: String, requireUserPresence: Bool) throws -> CreateOutput {
        // Validate the destination first so a refused path never costs a key.
        try KeyFileStore.checkCreatable(keyFile)
        try requireSecureEnclave()
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if requireUserPresence {
            var error: NSError?
            guard LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error) else {
                throw ErrorClassifier.authError(
                    "user presence cannot be verified on this Mac",
                    error ?? AuthError(code: .other, message: "no error reported"),
                    fallback: .other)
            }
            flags.insert(.userPresence)
        }

        var accessControlError: Unmanaged<CFError>?
        guard
            let accessControl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags,
                &accessControlError)
        else {
            let error: Error = accessControlError?.takeRetainedValue()
                ?? AuthError(code: .other, message: "no error reported")
            throw ErrorClassifier.authError("failed to create access control", error, fallback: .other)
        }

        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
        } catch {
            throw ErrorClassifier.authError(
                "failed to create the Secure Enclave key", error, fallback: .secureEnclaveUnavailable)
        }
        let publicKeySec1 = key.publicKey.x963Representation
        let contents = try KeyFileStore.encode(
            publicKeySec1: publicKeySec1, dataRepresentation: key.dataRepresentation)
        try KeyFileStore.writeNew(keyFile, contents: contents)
        return CreateOutput(publicKeySec1Hex: Hex.encode(publicKeySec1))
    }

    /// Signs `messageHex` with the key in `keyFile` after a user-presence prompt showing
    /// `reason`. With `allowUI == false` the prompt is forbidden, so a key that needs one fails
    /// with `interaction_not_allowed` instead of signing.
    static func sign(keyFile: String, reason: String, messageHex: String, allowUI: Bool) throws
        -> SignOutput
    {
        try Validation.checkReason(reason)
        let message = try Validation.message(fromHex: messageHex)
        let stored = try KeyFileStore.read(keyFile)
        try requireSecureEnclave()

        let context = LAContext()
        context.localizedReason = reason
        context.interactionNotAllowed = !allowUI
        let key: SecureEnclave.P256.Signing.PrivateKey
        do {
            key = try SecureEnclave.P256.Signing.PrivateKey(
                dataRepresentation: stored.dataRepresentation, authenticationContext: context)
        } catch {
            // A blob the Secure Enclave cannot unwrap is no longer usable.
            throw ErrorClassifier.authError(
                "failed to load the Secure Enclave key", error, fallback: .keyInvalidated)
        }
        // Never sign with a key other than the one the daemon has pinned.
        guard key.publicKey.x963Representation == stored.publicKeySec1 else {
            throw AuthError(
                code: .keyInvalidated,
                message: "the Secure Enclave key does not match the public key stored in \(keyFile)")
        }

        let signature: P256.Signing.ECDSASignature
        do {
            signature = try key.signature(for: message)
        } catch {
            throw ErrorClassifier.authError("Secure Enclave signing failed", error, fallback: .other)
        }
        guard stored.publicKey.isValidSignature(signature, for: message) else {
            throw AuthError(
                code: .keyInvalidated,
                message: "the Secure Enclave signature does not verify under the stored public key")
        }
        return SignOutput(signatureDerHex: Hex.encode(signature.derRepresentation))
    }

    /// Deletes the key file, destroying the admin key.
    static func delete(keyFile: String) throws -> DeleteOutput {
        try KeyFileStore.remove(keyFile)
        return DeleteOutput(deleted: true)
    }

    private static func requireSecureEnclave() throws {
        guard SecureEnclave.isAvailable else {
            throw AuthError(code: .secureEnclaveUnavailable, message: "this Mac has no usable Secure Enclave")
        }
    }
}

// MARK: - Command line

/// Parsed `--name value`, `--name=value` and `--flag` options of one subcommand.
struct Options {
    private var values: [String: String] = [:]
    private var flags: Set<String> = []

    init(_ arguments: ArraySlice<String>, values valueNames: Set<String>, flags flagNames: Set<String>) throws {
        var remaining = arguments.makeIterator()
        while let argument = remaining.next() {
            var name = argument
            var inlineValue: String?
            if argument.hasPrefix("--"), let equals = argument.firstIndex(of: "=") {
                name = String(argument[..<equals])
                inlineValue = String(argument[argument.index(after: equals)...])
            }
            if valueNames.contains(name) {
                guard let value = inlineValue ?? remaining.next() else {
                    throw AuthError.invalidInput("\(name) needs a value")
                }
                guard values.updateValue(value, forKey: name) == nil else {
                    throw AuthError.invalidInput("\(name) was given more than once")
                }
            } else if flagNames.contains(name), inlineValue == nil {
                guard flags.insert(name).inserted else {
                    throw AuthError.invalidInput("\(name) was given more than once")
                }
            } else {
                throw AuthError.invalidInput("unexpected argument \(argument); see `agentpay-auth help`")
            }
        }
    }

    func required(_ name: String) throws -> String {
        guard let value = values[name] else { throw AuthError.invalidInput("missing required option \(name)") }
        return value
    }

    func flag(_ name: String) -> Bool { flags.contains(name) }
}

enum AgentPayAuth {
    static let usage = """
        agentpay-auth: Secure Enclave admin key for AgentPay approvals (Touch ID or login password)

        USAGE:
          agentpay-auth status
          agentpay-auth create --key-file <path>
          agentpay-auth sign --key-file <path> --reason <text> --message-hex <hex> [--no-ui]
          agentpay-auth delete --key-file <path>

        Every command prints one JSON object on stdout. Failures print
        {"error":{"code":"...","message":"..."}} and exit with status 1.

        --no-ui  Fail with interaction_not_allowed instead of showing a prompt.
        """

    /// Runs the command line and returns the process exit status.
    static func main(_ arguments: [String]) -> Int32 {
        let arguments = arguments.dropFirst()
        if let first = arguments.first, ["help", "--help", "-h"].contains(first) {
            print(usage)
            return 0
        }
        do {
            try emit(run(arguments))
            return 0
        } catch {
            let failure = error as? AuthError ?? AuthError(code: .other, message: String(describing: error))
            struct Body: Encodable {
                let code: ErrorCode
                let message: String
            }
            struct Failure: Encodable { let error: Body }
            try? emit(Failure(error: Body(code: failure.code, message: failure.message)))
            return 1
        }
    }

    private static func run(_ arguments: ArraySlice<String>) throws -> any Encodable {
        guard let command = arguments.first else {
            throw AuthError.invalidInput("missing command; see `agentpay-auth help`")
        }
        let rest = arguments.dropFirst()
        switch command {
        case "status":
            _ = try Options(rest, values: [], flags: [])
            return Commands.status()
        case "create":
            // `--no-user-presence` is deliberately undocumented: it exists for automated tests.
            let options = try Options(rest, values: ["--key-file"], flags: ["--no-user-presence"])
            return try Commands.create(
                keyFile: options.required("--key-file"),
                requireUserPresence: !options.flag("--no-user-presence"))
        case "sign":
            let options = try Options(
                rest, values: ["--key-file", "--reason", "--message-hex"], flags: ["--no-ui"])
            return try Commands.sign(
                keyFile: options.required("--key-file"),
                reason: options.required("--reason"),
                messageHex: options.required("--message-hex"),
                allowUI: !options.flag("--no-ui"))
        case "delete":
            let options = try Options(rest, values: ["--key-file"], flags: [])
            return try Commands.delete(keyFile: options.required("--key-file"))
        default:
            throw AuthError.invalidInput("unknown command \(command); see `agentpay-auth help`")
        }
    }

    /// Writes `value` as one line of compact JSON to stdout.
    private static func emit(_ value: any Encodable) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        FileHandle.standardOutput.write(try encoder.encode(value) + Data("\n".utf8))
    }
}

exit(AgentPayAuth.main(CommandLine.arguments))
