# Changelog

All notable changes to zsig will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.1] - 2025-01-26

### 🔧 **HOTFIX: zcrypto v0.2.0 Compatibility Issues**

#### Fixed
- **Build Errors**: Fixed missing `blk:` labels in CLI argument parsing (src/cli.zig:541, 663)
- **Print Statements**: Updated all `print()` calls to include format argument tuples `.{}`
- **Deprecated APIs**: Replaced `std.mem.split()` with `std.mem.splitScalar()`
- **Ed25519 Key Generation**: Fixed non-existent `fromSeed()` calls - now uses `generateDeterministic()`
- **Array Size Mismatches**: Corrected Ed25519 key array size handling (32-byte seed → 64-byte private key)
- **Secp256k1/r1 Keys**: Fixed compressed public key handling (33-byte → 32-byte conversion)
- **Type Consistency**: Resolved struct type mismatches in HMAC functions
- **Memory Management**: Removed unused `allocator` variables in test functions

#### Technical Changes
- Ed25519 now uses `std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed)`
- Updated key field names from `secret_key` to `private_key` for zcrypto v0.2.0
- Fixed secp256k1/r1 function call signatures (removed unnecessary `&` operators)
- Improved error handling for seed-based key generation

#### Testing
- Verified multi-algorithm signing and verification
- Validated HMAC authentication workflows  
- Confirmed CLI operations (sign, verify, keygen)
- Tested cross-algorithm compatibility

## [0.2.0] - 2025-01-25

### 🚀 **MAJOR RELEASE: zcrypto Integration & Multi-Algorithm Support**

This is a major breaking release that transforms zsig from a simple Ed25519-only library into a comprehensive multi-algorithm cryptographic signing engine powered by zcrypto v0.2.0.

### Added

#### 🔐 **Multi-Algorithm Signature Support**
- **Ed25519** - Fast, secure, deterministic (enhanced with zcrypto)
- **secp256k1** - Bitcoin/Ethereum compatible signatures
- **secp256r1 (P-256)** - NIST standard curve support
- Unified `MultiSig` API for cross-algorithm operations
- Deterministic key generation from seeds for all algorithms

#### 🛡️ **HMAC Authentication**
- Message integrity verification using `zcrypto.auth.hmac.sha256`
- Authenticated signing with combined signature + HMAC tag
- Constant-time HMAC verification to prevent timing attacks
- CLI support for HMAC operations (`zsig hmac` command)

#### 🔧 **Enhanced Security Features**
- Constant-time cryptographic operations
- Secure memory clearing (`zcrypto.util.secureZero`)
- Cryptographically secure random generation
- Key derivation functions (HKDF, PBKDF2, Argon2id support via zcrypto)

#### 💻 **Extended CLI Interface**
- `zsig multisig` - Multi-algorithm signing and verification
- `zsig hmac` - HMAC authenticated operations
- `--algorithm` flag supporting `ed25519`, `secp256k1`, `secp256r1`
- `--hmac-key` flag for authentication
- `--seed` flag for deterministic key generation
- Enhanced help and version information

#### 🏦 **zwallet Integration Ready**
- Bitcoin transaction signing via secp256k1
- Deterministic HD wallet key derivation
- HMAC wallet protection mechanisms
- Compatible with BIP-39/32/44 standards (via zcrypto)

### Changed

#### 🔄 **Breaking Changes**
- **Dependency**: Now requires `zcrypto` as primary crypto backend
- **Default Backend**: Uses `ZCryptoInterface` instead of `ExampleStdCryptoInterface`
- **API Extensions**: Added multi-algorithm support alongside existing Ed25519 API
- **Build System**: Updated `build.zig` and `build.zig.zon` for zcrypto integration

#### 📈 **Improvements**
- **Deterministic Operations**: True deterministic key generation with zcrypto
- **Performance**: Optimized cryptographic operations via zcrypto
- **Security**: Enhanced with constant-time operations and secure memory handling
- **Documentation**: Comprehensive examples for multi-algorithm usage

### Enhanced

#### 🧪 **Testing Suite**
- Multi-algorithm integration tests
- HMAC authentication test coverage
- zwallet compatibility tests
- Cross-algorithm verification tests
- Deterministic operation validation

#### 📚 **Documentation**
- Updated library description and examples
- Multi-algorithm usage patterns
- HMAC authentication workflows
- CLI command documentation
- zwallet integration guide

### Technical Details

#### 🔧 **New Modules**
- `src/zsig/zcrypto_backend.zig` - Comprehensive zcrypto integration
- `ZCryptoKeypair` - Multi-algorithm keypair support
- `MultiSig` API - Unified multi-algorithm interface
- `HmacAuth` utilities - HMAC authentication helpers
- `SecureUtils` - Cryptographic utilities

#### 🏗️ **Architecture**
- Maintained backward compatibility with existing Ed25519 API
- Pluggable crypto backend system (existing + new zcrypto backend)
- Modular design supporting future algorithm additions
- Clean separation between crypto backends and application logic

#### 🎯 **Feature Flags**
```zig
pub const features = struct {
    pub const zcrypto_multisig = true;  // Multi-algorithm support
    pub const hmac_auth = true;         // HMAC authentication
    pub const secp256k1 = true;         // Bitcoin/Ethereum support
    pub const secp256r1 = true;         // NIST P-256 support
};
```

### Migration Guide

#### From v0.1.x to v0.2.0

**For Existing Ed25519 Users:**
```zig
// Old (still works)
zsig.setCryptoInterface(zsig.ExampleStdCryptoInterface.getInterface());

// New (recommended)
zsig.setCryptoInterface(zsig.ZCryptoInterface.getInterface());
```

**For New Multi-Algorithm Users:**
```zig
// Bitcoin-style signing
const bitcoin_kp = try zsig.MultiSig.generateKeypair(.secp256k1);
const signature = zsig.MultiSig.sign(tx_hash, bitcoin_kp);

// HMAC authentication
const auth_result = zsig.MultiSig.signWithHmac(message, keypair, hmac_key);
```

### Dependencies

- **Added**: `zcrypto` v0.2.0 - Comprehensive cryptographic library
- **Maintained**: No external C dependencies
- **Compatible**: Zig 0.15.0-dev.822+

### Compatibility

- ✅ **Backward Compatible**: Existing Ed25519 API unchanged
- ✅ **WASM Ready**: All algorithms support WASM compilation
- ✅ **Embedded Friendly**: Maintained low memory footprint
- ✅ **zwallet Ready**: Full integration support for wallet operations

---

## [0.1.0] - 2024-XX-XX

### Added
- Initial Ed25519 cryptographic signing implementation
- Basic keypair generation and management
- Detached and inline signature support
- CLI interface with keygen, sign, verify commands
- Pluggable crypto backend system
- WASM and embedded compatibility
- Comprehensive test suite

### Features
- Ed25519 signing and verification
- Public/private keypair generation
- Deterministic signing for audit trails
- Context-separated signing
- Base64 and hex output formats
- File-based key management

---

## Future Roadmap

### Planned for v0.3.0
- Hardware security module (HSM) support
- Multi-signature threshold schemes
- Advanced key derivation (BIP-32/44 native support)
- Performance optimizations
- Additional curve support (Curve25519, etc.)

### Long-term Goals
- Quantum-resistant signatures (post-quantum cryptography)
- Zero-knowledge proof integration
- Advanced authentication schemes
- Enterprise key management features

---

**Full Changelog**: https://github.com/ghostkellz/zsig/compare/v0.1.0...v0.2.0