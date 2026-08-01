import CryptoKit
import Foundation

struct VectorEntry: Decodable {
    let deviceID: String
    let counter: String

    enum CodingKeys: String, CodingKey {
        case deviceID = "device_id"
        case counter
    }
}

struct RecordCase: Decodable {
    let revisionID: String
    let authorCounter: String
    let tombstone: Bool
    let versionVector: [VectorEntry]
    let collectionWitnessAuthenticatorKind: Int
    let collectionWitnessAuthenticator: String?
    let recordNonceHex: String

    enum CodingKeys: String, CodingKey {
        case revisionID = "revision_id"
        case authorCounter = "author_counter"
        case tombstone
        case versionVector = "version_vector"
        case collectionWitnessAuthenticatorKind = "collection_witness_authenticator_kind"
        case collectionWitnessAuthenticator = "collection_witness_authenticator"
        case recordNonceHex = "record_nonce_hex"
    }
}

struct VectorInputs: Decodable {
    let protocolMajor: UInt16
    let cryptoSuiteID: UInt16
    let instanceID: String
    let vaultID: String
    let recordID: String
    let deviceID: String
    let recordCases: [String: RecordCase]
    let instanceSecretHex: String
    let vmkHex: String
    let hkdfSaltHex: String
    let argon2SaltHex: String
    let passphraseUTF8HexAfterNFC: String
    let envelopeNonceHex: String
    let recordPlaintextUTF8Hex: String

    enum CodingKeys: String, CodingKey {
        case protocolMajor = "protocol_major"
        case cryptoSuiteID = "crypto_suite_id"
        case instanceID = "instance_id"
        case vaultID = "vault_id"
        case recordID = "record_id"
        case deviceID = "device_id"
        case recordCases = "record_cases"
        case instanceSecretHex = "instance_secret_hex"
        case vmkHex = "vmk_hex"
        case hkdfSaltHex = "hkdf_salt_hex"
        case argon2SaltHex = "argon2_salt_hex"
        case passphraseUTF8HexAfterNFC = "passphrase_utf8_hex_after_nfc"
        case envelopeNonceHex = "envelope_nonce_hex"
        case recordPlaintextUTF8Hex = "record_plaintext_utf8_hex"
    }
}

struct Argon2Parameters: Decodable {
    let version: UInt32
    let memoryKiB: UInt32
    let iterations: UInt32
    let parallelism: UInt32
    let outputLength: UInt32

    enum CodingKeys: String, CodingKey {
        case version
        case memoryKiB = "memory_kib"
        case iterations
        case parallelism
        case outputLength = "output_length"
    }
}

struct VectorFixture: Decodable {
    let proposedSuite: String
    let inputs: VectorInputs
    let proposedArgon2ID: Argon2Parameters

    enum CodingKeys: String, CodingKey {
        case proposedSuite = "proposed_suite"
        case inputs
        case proposedArgon2ID = "proposed_argon2id"
    }
}

struct EnvelopeReference: Decodable {
    let envelopeGeneration: String
    let instanceSecretGeneration: String
    let mode: String

    enum CodingKeys: String, CodingKey {
        case envelopeGeneration = "envelope_generation"
        case instanceSecretGeneration = "instance_secret_generation"
        case mode
    }
}

struct EnvelopeCase: Decodable {
    let envelope: EnvelopeReference
}

struct EnvelopeFixture: Decodable {
    let baseMode: EnvelopeCase
    let passphraseRewrap: EnvelopeCase

    enum CodingKeys: String, CodingKey {
        case baseMode = "base_mode"
        case passphraseRewrap = "passphrase_rewrap"
    }
}

struct Outputs: Encodable {
    let baseWrapKeyHex: String
    let baseEnvelopeADHex: String
    let baseWrappedVMKHex: String
    let passphraseMaterialHex: String
    let passphraseWrapKeyHex: String
    let passphraseWrappedVMKHex: String
    let recordKeyHex: String
    let collectionWitnessKeyHex: String
    let authorizedCollectionWitnessAuthenticatorBase64URL: String
    let initialLiveRecordADHex: String
    let initialLiveRecordCiphertextHex: String
    let authorizedSupersedingRecordADHex: String
    let authorizedSupersedingRecordCiphertextHex: String
    let tamperedADResult: String
    let wrongPassphraseResult: String
    let rewrapPreservesVMK: Bool

    enum CodingKeys: String, CodingKey {
        case baseWrapKeyHex = "base_wrap_key_hex"
        case baseEnvelopeADHex = "base_envelope_ad_hex"
        case baseWrappedVMKHex = "base_wrapped_vmk_hex"
        case passphraseMaterialHex = "passphrase_material_hex"
        case passphraseWrapKeyHex = "passphrase_wrap_key_hex"
        case passphraseWrappedVMKHex = "passphrase_wrapped_vmk_hex"
        case recordKeyHex = "record_key_hex"
        case collectionWitnessKeyHex = "collection_witness_key_hex"
        case authorizedCollectionWitnessAuthenticatorBase64URL = "authorized_collection_witness_authenticator_base64url"
        case initialLiveRecordADHex = "initial_live_record_ad_hex"
        case initialLiveRecordCiphertextHex = "initial_live_record_ciphertext_hex"
        case authorizedSupersedingRecordADHex = "authorized_superseding_record_ad_hex"
        case authorizedSupersedingRecordCiphertextHex = "authorized_superseding_record_ciphertext_hex"
        case tamperedADResult = "tampered_ad_result"
        case wrongPassphraseResult = "wrong_passphrase_result"
        case rewrapPreservesVMK = "rewrap_preserves_vmk"
    }
}

enum KATError: Error, CustomStringConvertible {
    case invalidHex(String)
    case invalidUUID(String)
    case invalidInput(String)
    case opensslFailure(String)
    case authenticationUnexpectedlySucceeded(String)

    var description: String {
        switch self {
        case let .invalidHex(value): "invalid hex: \(value)"
        case let .invalidUUID(value): "invalid UUID: \(value)"
        case let .invalidInput(value): "invalid input: \(value)"
        case let .opensslFailure(value): "OpenSSL Argon2id failed: \(value)"
        case let .authenticationUnexpectedlySucceeded(value):
            "authentication unexpectedly succeeded: \(value)"
        }
    }
}

extension Array where Element == UInt8 {
    init(hex: String) throws {
        guard hex.count.isMultiple(of: 2) else {
            throw KATError.invalidHex(hex)
        }
        var result: [UInt8] = []
        result.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let value = UInt8(hex[index ..< next], radix: 16) else {
                throw KATError.invalidHex(hex)
            }
            result.append(value)
            index = next
        }
        self = result
    }

    var hex: String {
        map { String(format: "%02x", $0) }.joined()
    }
}

func uuidBytes(_ value: String) throws -> [UInt8] {
    let decoded = try [UInt8](hex: value.replacingOccurrences(of: "-", with: ""))
    guard decoded.count == 16 else {
        throw KATError.invalidUUID(value)
    }
    return decoded
}

func appendU8(_ target: inout [UInt8], _ value: UInt8) {
    target.append(value)
}

func appendU16(_ target: inout [UInt8], _ value: UInt16) {
    target.append(UInt8((value >> 8) & 0xff))
    target.append(UInt8(value & 0xff))
}

func appendU32(_ target: inout [UInt8], _ value: UInt32) {
    target.append(UInt8((value >> 24) & 0xff))
    target.append(UInt8((value >> 16) & 0xff))
    target.append(UInt8((value >> 8) & 0xff))
    target.append(UInt8(value & 0xff))
}

func appendU64(_ target: inout [UInt8], _ value: UInt64) {
    for shift in stride(from: 56, through: 0, by: -8) {
        target.append(UInt8((value >> UInt64(shift)) & 0xff))
    }
}

func appendLP(_ target: inout [UInt8], _ value: [UInt8]) {
    appendU32(&target, UInt32(value.count))
    target.append(contentsOf: value)
}

func hkdfExtract(salt: [UInt8], ikm: [UInt8]) -> [UInt8] {
    let code = HMAC<SHA256>.authenticationCode(
        for: Data(ikm),
        using: SymmetricKey(data: Data(salt))
    )
    return Array(code)
}

func hkdfExpand32(prk: [UInt8], info: [UInt8]) -> [UInt8] {
    var input = info
    input.append(1)
    let code = HMAC<SHA256>.authenticationCode(
        for: Data(input),
        using: SymmetricKey(data: Data(prk))
    )
    return Array(code)
}

func wrapKey(fixture: VectorFixture, mode: UInt8, passphraseMaterial: [UInt8]) throws -> [UInt8] {
    let instanceSecret = try [UInt8](hex: fixture.inputs.instanceSecretHex)
    let salt = try [UInt8](hex: fixture.inputs.hkdfSaltHex)
    var ikm: [UInt8] = []
    appendLP(&ikm, instanceSecret)
    appendLP(&ikm, passphraseMaterial)
    let prk = hkdfExtract(salt: salt, ikm: ikm)
    var info: [UInt8] = []
    appendLP(&info, Array("JAT vault wrapping key v1".utf8))
    info.append(contentsOf: try uuidBytes(fixture.inputs.instanceID))
    info.append(contentsOf: try uuidBytes(fixture.inputs.vaultID))
    appendU8(&info, mode)
    return hkdfExpand32(prk: prk, info: info)
}

func envelopeAD(fixture: VectorFixture, reference: EnvelopeReference) throws -> [UInt8] {
    let mode: UInt8
    let argonSalt: [UInt8]
    let version: UInt32
    let memory: UInt32
    let iterations: UInt32
    let parallelism: UInt32
    switch reference.mode {
    case "base":
        mode = 0
        argonSalt = []
        version = 0
        memory = 0
        iterations = 0
        parallelism = 0
    case "passphrase":
        mode = 1
        argonSalt = try [UInt8](hex: fixture.inputs.argon2SaltHex)
        version = fixture.proposedArgon2ID.version
        memory = fixture.proposedArgon2ID.memoryKiB
        iterations = fixture.proposedArgon2ID.iterations
        parallelism = fixture.proposedArgon2ID.parallelism
    default:
        throw KATError.invalidInput("unknown envelope mode")
    }
    guard let envelopeGeneration = UInt64(reference.envelopeGeneration),
          let secretGeneration = UInt64(reference.instanceSecretGeneration)
    else {
        throw KATError.invalidInput("non-canonical envelope generation")
    }

    var ad: [UInt8] = []
    appendLP(&ad, Array("JAT vault envelope AD v1".utf8))
    appendU16(&ad, fixture.inputs.protocolMajor)
    appendU16(&ad, fixture.inputs.cryptoSuiteID)
    ad.append(contentsOf: try uuidBytes(fixture.inputs.instanceID))
    ad.append(contentsOf: try uuidBytes(fixture.inputs.vaultID))
    appendU64(&ad, envelopeGeneration)
    appendU64(&ad, secretGeneration)
    appendU8(&ad, mode)
    appendLP(&ad, try [UInt8](hex: fixture.inputs.hkdfSaltHex))
    appendLP(&ad, argonSalt)
    appendU32(&ad, version)
    appendU32(&ad, memory)
    appendU32(&ad, iterations)
    appendU32(&ad, parallelism)
    return ad
}

func recordKey(fixture: VectorFixture, label: String) throws -> [UInt8] {
    let vmk = try [UInt8](hex: fixture.inputs.vmkHex)
    let prk = hkdfExtract(salt: try uuidBytes(fixture.inputs.recordID), ikm: vmk)
    var info: [UInt8] = []
    appendLP(&info, Array(label.utf8))
    appendU16(&info, fixture.inputs.protocolMajor)
    appendU16(&info, fixture.inputs.cryptoSuiteID)
    info.append(contentsOf: try uuidBytes(fixture.inputs.instanceID))
    info.append(contentsOf: try uuidBytes(fixture.inputs.vaultID))
    info.append(contentsOf: try uuidBytes(fixture.inputs.recordID))
    return hkdfExpand32(prk: prk, info: info)
}

func canonicalVector(_ entries: [VectorEntry]) throws -> [VectorEntry] {
    try entries.sorted { left, right in
        try uuidBytes(left.deviceID).lexicographicallyPrecedes(uuidBytes(right.deviceID))
    }
}

func witnessAuthenticator(
    fixture: VectorFixture,
    key: [UInt8],
    test: RecordCase
) throws -> [UInt8] {
    var message: [UInt8] = []
    appendLP(&message, Array("JAT collection witness authenticator v1".utf8))
    appendU16(&message, fixture.inputs.protocolMajor)
    appendU16(&message, fixture.inputs.cryptoSuiteID)
    message.append(contentsOf: try uuidBytes(fixture.inputs.instanceID))
    message.append(contentsOf: try uuidBytes(fixture.inputs.vaultID))
    message.append(contentsOf: try uuidBytes(fixture.inputs.recordID))
    message.append(contentsOf: try uuidBytes(test.revisionID))
    let vector = try canonicalVector(test.versionVector)
    appendU16(&message, UInt16(vector.count))
    for entry in vector {
        guard let counter = UInt64(entry.counter) else {
            throw KATError.invalidInput("invalid vector counter")
        }
        message.append(contentsOf: try uuidBytes(entry.deviceID))
        appendU64(&message, counter)
    }
    return Array(HMAC<SHA256>.authenticationCode(
        for: Data(message),
        using: SymmetricKey(data: Data(key))
    ))
}

func recordAD(fixture: VectorFixture, test: RecordCase, authenticator: [UInt8]) throws -> [UInt8] {
    guard let authorCounter = UInt64(test.authorCounter) else {
        throw KATError.invalidInput("invalid author counter")
    }
    var ad: [UInt8] = []
    appendLP(&ad, Array("JAT record revision AD v1".utf8))
    appendU16(&ad, fixture.inputs.protocolMajor)
    appendU16(&ad, fixture.inputs.cryptoSuiteID)
    ad.append(contentsOf: try uuidBytes(fixture.inputs.instanceID))
    ad.append(contentsOf: try uuidBytes(fixture.inputs.vaultID))
    ad.append(contentsOf: try uuidBytes(fixture.inputs.recordID))
    ad.append(contentsOf: try uuidBytes(test.revisionID))
    ad.append(contentsOf: try uuidBytes(fixture.inputs.deviceID))
    appendU64(&ad, authorCounter)
    appendU16(&ad, 1)
    appendU8(&ad, test.tombstone ? 1 : 0)
    let vector = try canonicalVector(test.versionVector)
    appendU16(&ad, UInt16(vector.count))
    for entry in vector {
        guard let counter = UInt64(entry.counter) else {
            throw KATError.invalidInput("invalid vector counter")
        }
        ad.append(contentsOf: try uuidBytes(entry.deviceID))
        appendU64(&ad, counter)
    }
    appendU8(&ad, UInt8(test.collectionWitnessAuthenticatorKind))
    switch test.collectionWitnessAuthenticatorKind {
    case 0:
        break
    case 1:
        guard authenticator.count == 32 else {
            throw KATError.invalidInput("authorized witness must contain 32 bytes")
        }
        ad.append(contentsOf: authenticator)
    default:
        throw KATError.invalidInput("unsupported witness kind")
    }
    return ad
}

func rotateLeft(_ value: UInt32, by count: UInt32) -> UInt32 {
    (value << count) | (value >> (32 - count))
}

func quarterRound(_ state: inout [UInt32], _ a: Int, _ b: Int, _ c: Int, _ d: Int) {
    state[a] &+= state[b]
    state[d] ^= state[a]
    state[d] = rotateLeft(state[d], by: 16)
    state[c] &+= state[d]
    state[b] ^= state[c]
    state[b] = rotateLeft(state[b], by: 12)
    state[a] &+= state[b]
    state[d] ^= state[a]
    state[d] = rotateLeft(state[d], by: 8)
    state[c] &+= state[d]
    state[b] ^= state[c]
    state[b] = rotateLeft(state[b], by: 7)
}

func loadLE32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
    UInt32(bytes[offset])
        | UInt32(bytes[offset + 1]) << 8
        | UInt32(bytes[offset + 2]) << 16
        | UInt32(bytes[offset + 3]) << 24
}

func appendLE32(_ target: inout [UInt8], _ value: UInt32) {
    target.append(UInt8(value & 0xff))
    target.append(UInt8((value >> 8) & 0xff))
    target.append(UInt8((value >> 16) & 0xff))
    target.append(UInt8((value >> 24) & 0xff))
}

func hChaCha20(key: [UInt8], nonce: [UInt8]) throws -> [UInt8] {
    guard key.count == 32, nonce.count == 16 else {
        throw KATError.invalidInput("HChaCha20 requires a 32-byte key and 16-byte nonce")
    }
    var state: [UInt32] = [
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
    ]
    for offset in stride(from: 0, to: key.count, by: 4) {
        state.append(loadLE32(key, offset))
    }
    for offset in stride(from: 0, to: nonce.count, by: 4) {
        state.append(loadLE32(nonce, offset))
    }
    for _ in 0 ..< 10 {
        quarterRound(&state, 0, 4, 8, 12)
        quarterRound(&state, 1, 5, 9, 13)
        quarterRound(&state, 2, 6, 10, 14)
        quarterRound(&state, 3, 7, 11, 15)
        quarterRound(&state, 0, 5, 10, 15)
        quarterRound(&state, 1, 6, 11, 12)
        quarterRound(&state, 2, 7, 8, 13)
        quarterRound(&state, 3, 4, 9, 14)
    }
    var result: [UInt8] = []
    for index in [0, 1, 2, 3, 12, 13, 14, 15] {
        appendLE32(&result, state[index])
    }
    return result
}

func xNonce(_ nonce: [UInt8]) throws -> ChaChaPoly.Nonce {
    guard nonce.count == 24 else {
        throw KATError.invalidInput("XChaCha20-Poly1305 requires a 24-byte nonce")
    }
    var ietfNonce = [UInt8](repeating: 0, count: 4)
    ietfNonce.append(contentsOf: nonce.suffix(8))
    return try ChaChaPoly.Nonce(data: Data(ietfNonce))
}

func xSeal(key: [UInt8], nonce: [UInt8], plaintext: [UInt8], ad: [UInt8]) throws -> [UInt8] {
    let subkey = try hChaCha20(key: key, nonce: Array(nonce.prefix(16)))
    let box = try ChaChaPoly.seal(
        Data(plaintext),
        using: SymmetricKey(data: Data(subkey)),
        nonce: try xNonce(nonce),
        authenticating: Data(ad)
    )
    var combined = Data(box.ciphertext)
    combined.append(box.tag)
    return Array(combined)
}

func xOpen(key: [UInt8], nonce: [UInt8], ciphertext: [UInt8], ad: [UInt8]) throws -> [UInt8] {
    guard ciphertext.count >= 16 else {
        throw KATError.invalidInput("ciphertext is shorter than the authentication tag")
    }
    let subkey = try hChaCha20(key: key, nonce: Array(nonce.prefix(16)))
    let split = ciphertext.count - 16
    let box = try ChaChaPoly.SealedBox(
        nonce: try xNonce(nonce),
        ciphertext: Data(ciphertext[..<split]),
        tag: Data(ciphertext[split...])
    )
    return Array(try ChaChaPoly.open(
        box,
        using: SymmetricKey(data: Data(subkey)),
        authenticating: Data(ad)
    ))
}

func argon2ID(
    password: [UInt8],
    salt: [UInt8],
    parameters: Argon2Parameters
) throws -> [UInt8] {
    guard let opensslPath = ProcessInfo.processInfo.environment["JAT_OPENSSL_BIN"],
          opensslPath.hasPrefix("/")
    else {
        throw KATError.invalidInput(
            "JAT_OPENSSL_BIN must name the absolute reviewed OpenSSL 3 executable"
        )
    }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: opensslPath)
    process.arguments = [
        "kdf", "-binary",
        "-keylen", String(parameters.outputLength),
        "-kdfopt", "hexpass:\(password.hex)",
        "-kdfopt", "hexsalt:\(salt.hex)",
        "-kdfopt", "iter:\(parameters.iterations)",
        "-kdfopt", "lanes:\(parameters.parallelism)",
        "-kdfopt", "threads:1",
        "-kdfopt", "memcost:\(parameters.memoryKiB)",
        "-kdfopt", "version:\(parameters.version)",
        "ARGON2ID",
    ]
    let stdout = Pipe()
    let stderr = Pipe()
    process.standardOutput = stdout
    process.standardError = stderr
    try process.run()
    process.waitUntilExit()
    let output = stdout.fileHandleForReading.readDataToEndOfFile()
    let errorOutput = stderr.fileHandleForReading.readDataToEndOfFile()
    guard process.terminationStatus == 0 else {
        throw KATError.opensslFailure(String(decoding: errorOutput, as: UTF8.self))
    }
    guard output.count == parameters.outputLength else {
        throw KATError.opensslFailure("unexpected output length \(output.count)")
    }
    return Array(output)
}

func base64URL(_ bytes: [UInt8]) -> String {
    Data(bytes).base64EncodedString()
        .replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_")
        .replacingOccurrences(of: "=", with: "")
}

func derive(fixture: VectorFixture, envelopes: EnvelopeFixture) throws -> Outputs {
    guard fixture.proposedSuite == "jat-xchacha-hkdf-argon2id-draft2",
          fixture.proposedArgon2ID.version == 19,
          fixture.proposedArgon2ID.outputLength == 32
    else {
        throw KATError.invalidInput("unexpected approved suite")
    }
    let baseKey = try wrapKey(fixture: fixture, mode: 0, passphraseMaterial: [])
    let passphrase = try [UInt8](hex: fixture.inputs.passphraseUTF8HexAfterNFC)
    let argonSalt = try [UInt8](hex: fixture.inputs.argon2SaltHex)
    let material = try argon2ID(
        password: passphrase,
        salt: argonSalt,
        parameters: fixture.proposedArgon2ID
    )
    let passphraseKey = try wrapKey(fixture: fixture, mode: 1, passphraseMaterial: material)
    let baseAD = try envelopeAD(fixture: fixture, reference: envelopes.baseMode.envelope)
    let passphraseAD = try envelopeAD(
        fixture: fixture,
        reference: envelopes.passphraseRewrap.envelope
    )
    let nonce = try [UInt8](hex: fixture.inputs.envelopeNonceHex)
    let vmk = try [UInt8](hex: fixture.inputs.vmkHex)
    let baseCiphertext = try xSeal(key: baseKey, nonce: nonce, plaintext: vmk, ad: baseAD)
    let passphraseCiphertext = try xSeal(
        key: passphraseKey,
        nonce: nonce,
        plaintext: vmk,
        ad: passphraseAD
    )

    let recordKeyBytes = try recordKey(fixture: fixture, label: "JAT record key v1")
    let witnessKey = try recordKey(fixture: fixture, label: "JAT collection witness key v1")
    guard let initial = fixture.inputs.recordCases["initial_live_null_authorization"],
          let authorized = fixture.inputs.recordCases["authorized_superseding_live"]
    else {
        throw KATError.invalidInput("missing record case")
    }
    let authenticator = try witnessAuthenticator(fixture: fixture, key: witnessKey, test: authorized)
    let initialAD = try recordAD(fixture: fixture, test: initial, authenticator: [])
    let authorizedAD = try recordAD(
        fixture: fixture,
        test: authorized,
        authenticator: authenticator
    )
    let plaintext = try [UInt8](hex: fixture.inputs.recordPlaintextUTF8Hex)
    let initialCiphertext = try xSeal(
        key: recordKeyBytes,
        nonce: [UInt8](hex: initial.recordNonceHex),
        plaintext: plaintext,
        ad: initialAD
    )
    let authorizedCiphertext = try xSeal(
        key: recordKeyBytes,
        nonce: [UInt8](hex: authorized.recordNonceHex),
        plaintext: plaintext,
        ad: authorizedAD
    )

    var tamperedAD = baseAD
    tamperedAD[tamperedAD.count - 1] ^= 1
    do {
        _ = try xOpen(key: baseKey, nonce: nonce, ciphertext: baseCiphertext, ad: tamperedAD)
        throw KATError.authenticationUnexpectedlySucceeded("tampered associated data")
    } catch is CryptoKitError {
        // Expected authentication failure.
    }

    var wrongPassphrase = passphrase
    wrongPassphrase.append(0)
    let wrongMaterial = try argon2ID(
        password: wrongPassphrase,
        salt: argonSalt,
        parameters: fixture.proposedArgon2ID
    )
    let wrongKey = try wrapKey(fixture: fixture, mode: 1, passphraseMaterial: wrongMaterial)
    do {
        _ = try xOpen(
            key: wrongKey,
            nonce: nonce,
            ciphertext: passphraseCiphertext,
            ad: passphraseAD
        )
        throw KATError.authenticationUnexpectedlySucceeded("wrong passphrase")
    } catch is CryptoKitError {
        // Expected authentication failure.
    }

    let basePlaintext = try xOpen(
        key: baseKey,
        nonce: nonce,
        ciphertext: baseCiphertext,
        ad: baseAD
    )
    let passphrasePlaintext = try xOpen(
        key: passphraseKey,
        nonce: nonce,
        ciphertext: passphraseCiphertext,
        ad: passphraseAD
    )

    return Outputs(
        baseWrapKeyHex: baseKey.hex,
        baseEnvelopeADHex: baseAD.hex,
        baseWrappedVMKHex: baseCiphertext.hex,
        passphraseMaterialHex: material.hex,
        passphraseWrapKeyHex: passphraseKey.hex,
        passphraseWrappedVMKHex: passphraseCiphertext.hex,
        recordKeyHex: recordKeyBytes.hex,
        collectionWitnessKeyHex: witnessKey.hex,
        authorizedCollectionWitnessAuthenticatorBase64URL: base64URL(authenticator),
        initialLiveRecordADHex: initialAD.hex,
        initialLiveRecordCiphertextHex: initialCiphertext.hex,
        authorizedSupersedingRecordADHex: authorizedAD.hex,
        authorizedSupersedingRecordCiphertextHex: authorizedCiphertext.hex,
        tamperedADResult: "authentication_failed",
        wrongPassphraseResult: "authentication_failed",
        rewrapPreservesVMK: basePlaintext == vmk && passphrasePlaintext == vmk
    )
}

func load<T: Decodable>(_ type: T.Type, path: String) throws -> T {
    let data = try Data(contentsOf: URL(fileURLWithPath: path))
    return try JSONDecoder().decode(type, from: data)
}

guard CommandLine.arguments.count == 3 else {
    fputs("usage: CryptoKAT.swift <crypto-review-vectors.json> <vault-envelope.json>\n", stderr)
    exit(2)
}

do {
    let fixture = try load(VectorFixture.self, path: CommandLine.arguments[1])
    let envelopes = try load(EnvelopeFixture.self, path: CommandLine.arguments[2])
    let output = try derive(fixture: fixture, envelopes: envelopes)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
    let data = try encoder.encode(output)
    print(String(decoding: data, as: UTF8.self))
} catch {
    fputs("crypto KAT failed: \(error)\n", stderr)
    exit(1)
}
