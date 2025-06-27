# 🛡️ RealID Documentation

**RealID** is a zero-trust identity framework built in Zig that provides cryptographic identity operations for decentralized applications, wallets, and authentication systems.

## 📋 Table of Contents

- [Core Concepts](#core-concepts)
- [API Reference](#api-reference)
- [Cryptographic Design](#cryptographic-design)
- [Examples](#examples)
- [Error Handling](#error-handling)
- [Security Considerations](#security-considerations)

## 🔑 Core Concepts

### Identity Generation
RealID generates deterministic identities from user passphrases using PBKDF2-SHA256 key derivation and Ed25519 elliptic curve cryptography.

### QID (QUIC Identity)
Stateless IPv6 addresses derived from public keys, enabling network-level identity resolution without centralized registries.

### Device Binding
Optional device fingerprinting adds an additional authentication factor, making identities device-specific.

### Zero-Trust Architecture
All operations are stateless and cryptographically verifiable without trusted third parties.

---

## 📚 API Reference

### Core Functions

#### `realid_generate_from_passphrase(passphrase: []const u8) RealIDError!RealIDKeyPair`

Generates a deterministic Ed25519 keypair from a passphrase.

**Parameters:**
- `passphrase` - UTF-8 encoded passphrase (minimum 1 character)

**Returns:**
- `RealIDKeyPair` containing 64-byte private key and 32-byte public key

**Example:**
```zig
const keypair = try realid.realid_generate_from_passphrase("my_secure_passphrase");
```

#### `realid_generate_from_passphrase_with_device(passphrase: []const u8, device_fingerprint: DeviceFingerprint) RealIDError!RealIDKeyPair`

Generates a device-bound keypair combining passphrase and device characteristics.

**Parameters:**
- `passphrase` - UTF-8 encoded passphrase
- `device_fingerprint` - 32-byte device fingerprint

**Returns:**
- Device-specific `RealIDKeyPair`

**Example:**
```zig
const device_fp = try realid.generate_device_fingerprint(allocator);
const keypair = try realid.realid_generate_from_passphrase_with_device("passphrase", device_fp);
```

### Signing & Verification

#### `realid_sign(data: []const u8, private_key: RealIDPrivateKey) RealIDError!RealIDSignature`

Signs arbitrary data with Ed25519.

**Parameters:**
- `data` - Bytes to sign
- `private_key` - 64-byte RealID private key

**Returns:**
- 64-byte Ed25519 signature

**Example:**
```zig
const message = "Hello, RealID!";
const signature = try realid.realid_sign(message, keypair.private_key);
```

#### `realid_verify(signature: RealIDSignature, data: []const u8, public_key: RealIDPublicKey) bool`

Verifies an Ed25519 signature.

**Parameters:**
- `signature` - 64-byte signature to verify
- `data` - Original signed data
- `public_key` - 32-byte public key

**Returns:**
- `true` if signature is valid, `false` otherwise

**Example:**
```zig
const is_valid = realid.realid_verify(signature, message, keypair.public_key);
```

### QID Operations

#### `realid_qid_from_pubkey(public_key: RealIDPublicKey) QID`

Generates a stateless IPv6 QID from a public key.

**Parameters:**
- `public_key` - 32-byte Ed25519 public key

**Returns:**
- 16-byte IPv6 address with `fd00::/8` prefix

**Example:**
```zig
const qid = realid.realid_qid_from_pubkey(keypair.public_key);
```

#### `qid_to_string(qid: QID, buffer: []u8) ![]u8`

Converts QID to IPv6 string representation.

**Parameters:**
- `qid` - 16-byte QID
- `buffer` - Output buffer (minimum 39 bytes)

**Returns:**
- IPv6 string (e.g., `fd00:1234:5678:9abc:def0:1234:5678:9abc`)

### Device Fingerprinting

#### `generate_device_fingerprint(allocator: std.mem.Allocator) RealIDError!DeviceFingerprint`

Generates a deterministic device fingerprint from system characteristics.

**Parameters:**
- `allocator` - Memory allocator

**Returns:**
- 32-byte device fingerprint

**System Factors:**
- Hostname / Computer name
- Username
- Current working directory
- Operating system type

---

## 🔐 Cryptographic Design

### Key Derivation

```
Passphrase + Salt → PBKDF2-SHA256(100,000 iterations) → 32-byte seed → Ed25519 KeyPair
```

**Salt Construction:**
```
Salt = SHA256("RealID-v1" || passphrase)
Salt (with device) = SHA256("RealID-v1" || device_fingerprint || passphrase)
```

### QID Generation

```
QID = fd00:: | SHA256("RealID-QID-v1" || public_key)[0:14]
```

### Device Fingerprint

```
Fingerprint = SHA256("RealID-Device-v1" || hostname || username || cwd || os_type)
```

---

## 💡 Examples

### Basic Identity Creation

```zig
const std = @import("std");
const realid = @import("realid");

pub fn main() !void {
    // Generate identity from passphrase
    const passphrase = "my_secure_passphrase_123";
    const keypair = try realid.realid_generate_from_passphrase(passphrase);
    
    // Display public key
    std.debug.print("Public Key: ");
    for (keypair.public_key.bytes) |byte| {
        std.debug.print("{x:0>2}", .{byte});
    }
    std.debug.print("\n");
    
    // Generate QID
    const qid = realid.realid_qid_from_pubkey(keypair.public_key);
    var qid_buffer: [64]u8 = undefined;
    const qid_str = try realid.qid.qid_to_string(qid, &qid_buffer);
    std.debug.print("QID: {s}\n", .{qid_str});
}
```

### Message Signing

```zig
const message = "Transaction: Send 100 tokens to Alice";
const signature = try realid.realid_sign(message, keypair.private_key);

// Verify signature
const is_valid = realid.realid_verify(signature, message, keypair.public_key);
std.debug.print("Signature valid: {}\n", .{is_valid});
```

### Device-Bound Identity

```zig
var gpa = std.heap.GeneralPurposeAllocator(.{}){};
defer _ = gpa.deinit();
const allocator = gpa.allocator();

// Generate device fingerprint
const device_fp = try realid.generate_device_fingerprint(allocator);

// Create device-bound identity
const device_keypair = try realid.realid_generate_from_passphrase_with_device(
    "my_passphrase", 
    device_fp
);

// This keypair will be different on different devices
```

---

## ⚠️ Error Handling

### Error Types

```zig
pub const RealIDError = error{
    InvalidPassphrase,    // Empty or invalid passphrase
    InvalidSignature,     // Signature verification failed
    InvalidPublicKey,     // Malformed public key
    InvalidPrivateKey,    // Malformed private key
    CryptoError,         // Underlying cryptographic error
    OutOfMemory,         // Memory allocation failed
};
```

### Error Handling Pattern

```zig
const keypair = realid.realid_generate_from_passphrase(passphrase) catch |err| {
    switch (err) {
        RealIDError.InvalidPassphrase => {
            std.debug.print("Passphrase cannot be empty\n");
            return;
        },
        RealIDError.CryptoError => {
            std.debug.print("Cryptographic operation failed\n");
            return;
        },
        RealIDError.OutOfMemory => {
            std.debug.print("Insufficient memory\n");
            return;
        },
        else => {
            std.debug.print("Unknown error: {}\n", .{err});
            return;
        },
    }
};
```

---

## 🔒 Security Considerations

### Passphrase Security

- **Minimum Length**: Use passphrases with sufficient entropy (>12 characters recommended)
- **Uniqueness**: Different passphrases for different applications/contexts
- **Storage**: Never store passphrases in plaintext

### Device Fingerprinting

- **Privacy**: Device fingerprints may reveal system information
- **Stability**: Fingerprints may change if system configuration changes
- **Binding**: Device-bound identities cannot be recovered on different devices

### Cryptographic Assumptions

- **Ed25519**: Assumes elliptic curve discrete logarithm problem is hard
- **SHA-256**: Assumes collision resistance and preimage resistance
- **PBKDF2**: 100,000 iterations provide protection against brute force attacks

### Memory Safety

- Private keys are stored in memory and should be zeroed after use
- Consider using secure memory allocation for sensitive operations
- Be aware of potential memory dumps in crash scenarios

### Network Security

- QIDs are derived from public keys and are not secret
- QID-to-identity mapping may reveal usage patterns
- Consider using onion routing or other privacy-preserving networks

---

## 🔧 Build Configuration

### Requirements

- Zig 0.15.0-dev.822 or later
- zcrypto library (included via zion package manager)

### Compilation Flags

```bash
# Debug build
zig build

# Release build
zig build -Doptimize=ReleaseFast

# Run tests
zig build test

# Run demo
zig build run
```

### Library Integration

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .realid = .{
        .url = "https://github.com/your-org/realid/archive/main.tar.gz",
        .hash = "...",
    },
},
```

---

## 📈 Performance Characteristics

### Key Generation

- **PBKDF2**: ~100ms on modern hardware (100,000 iterations)
- **Ed25519 KeyGen**: <1ms
- **Total**: ~100ms per identity generation

### Signing

- **Ed25519 Sign**: <1ms per signature
- **Memory**: ~1KB working memory

### Verification

- **Ed25519 Verify**: <1ms per verification
- **Batch Verification**: More efficient for multiple signatures

### QID Generation

- **SHA-256**: <1ms per QID
- **Memory**: Minimal (32 bytes working space)

---

## 🧪 Testing

Run the complete test suite:

```bash
zig build test
```

### Test Categories

- **Unit Tests**: Individual function testing
- **Integration Tests**: End-to-end workflows
- **Cryptographic Tests**: Known answer tests
- **Error Handling**: Error condition testing

### Test Vectors

The library includes test vectors for:
- Deterministic key generation
- Signature generation and verification  
- QID derivation
- Device fingerprinting

---

## 📖 References

- [RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)](https://tools.ietf.org/rfc/rfc8032.txt)
- [RFC 2898: PKCS #5: Password-Based Cryptography Specification Version 2.0](https://tools.ietf.org/rfc/rfc2898.txt)
- [RFC 4193: Unique Local IPv6 Unicast Addresses](https://tools.ietf.org/rfc/rfc4193.txt)
- [FIPS 180-4: Secure Hash Standard (SHS)](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)
