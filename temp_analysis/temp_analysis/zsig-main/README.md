# Zsig: Lightweight Cryptographic Signing Library for Zig

## 📌 Overview

**Zsig** is a **dependency-free** cryptographic signing library that accepts crypto function implementations from parent applications. Instead of bundling heavy crypto dependencies, zsig provides a clean interface that allows parent applications to provide their own crypto primitives.

This makes zsig extremely lightweight and flexible, perfect for integration into larger projects like `zwallet`, `zledger`, and other Ghost ecosystem components.

---

## 🎯 Goals

* 🪶 **Zero Dependencies**: Accept crypto functions from parent apps instead of bundling crypto libraries
* 🔌 **Pluggable Interface**: Works with any Ed25519 implementation (std.crypto, zcrypto, etc.)
* ⚡ **Lightweight**: Minimal overhead and fast compilation
* 🧱 **Zig-native**: Pure Zig with no external C dependencies
* 🔁 **Stateless**: Clean API for audit trails and deterministic workflows

---

## 🔧 Features

* ✅ Ed25519 signing
* ✅ Public/private keypair generation
* ✅ Detached or inline signatures
* ✅ Signature verification API
* ✅ CLI signer + key manager
* ✅ Optional deterministic keygen (brain wallets/passphrases)

---

## 🚀 Quick Start

### Step 1: Set up the crypto interface

Before using zsig, you must provide crypto function implementations:

```zig
const std = @import("std");
const zsig = @import("zsig");

// Use the built-in std.crypto implementation
pub fn main() !void {
    // Initialize zsig with std.crypto functions
    zsig.setCryptoInterface(zsig.ExampleStdCryptoInterface.getInterface());
    
    // Now you can use zsig functions
    const allocator = std.heap.page_allocator;
    const keypair = try zsig.generateKeypair(allocator);
    
    const message = "Hello, World!";
    const signature = try zsig.signMessage(message, keypair);
    const is_valid = zsig.verifySignature(message, &signature.bytes, &keypair.publicKey());
    
    std.debug.print("Signature valid: {}\n", .{is_valid});
}
```

### Step 2: Or provide your own crypto implementation

```zig
// Create custom crypto interface (e.g., using zcrypto)
const my_crypto_interface = zsig.CryptoInterface{
    .generateKeypairFn = myGenerateKeypair,
    .keypairFromSeedFn = myKeypairFromSeed,
    .signFn = mySign,
    .verifyFn = myVerify,
    .hashFn = myHash,
};

zsig.setCryptoInterface(my_crypto_interface);
```

---

## 🗂 Structure

### `zsig/key.zig`

Handles public/private key generation and formatting:

```zig
const Keypair = struct {
    public: [32]u8,
    private: [64]u8,
};
```

### `zsig/sign.zig`

Core signing logic:

```zig
pub fn sign(message: []const u8, keypair: Keypair) []u8 {...}
```

### `zsig/verify.zig`

Signature verification:

```zig
pub fn verify(message: []const u8, signature: []const u8, public_key: []const u8) bool {...}
```

---

## 🔐 Key Generation Examples

```sh
zsig keygen --out keys/alice.key
zsig keygen --seed "correct horse battery staple"
```

### Signature:

```sh
zsig sign --in tx.json --key keys/alice.key --out tx.sig
zsig verify --in tx.json --sig tx.sig --pubkey keys/alice.pub
```

---

## 🧠 Use Cases

* 🔐 Signed transactions (Zledger)
* 👛 Message authentication (Zwallet)
* 📦 Secure build signatures (Zmake/Zion)
* 📡 Node-to-node handshake validation (Ghostmesh)
* 📜 Sign Git commits in CLI (future Ghostforge use)

---

## 📦 Output Formats

* `.sig` = raw 64-byte Ed25519 signature
* `.pub` = 32-byte hex public key
* `.key` = base64 private + public bundle

---

## 🧪 Testing & Security

* Memory zeroing on key destruction
* Optional HMAC-style challenge for CLI workflows
* Fuzz-tested against known-good vectors (RFC 8032)

---

## 🔭 Future Plans

* 📡 Add support for ECDSA and Schnorr signatures
* 🔐 Multi-sig primitive for smart contract signing
* 🧩 zk-compatible proof helper tooling (ZKProof integration)
* 💾 Hardware wallet hooks (Yubikey, Ledger Nano via Zig bindings)

---

## 🔍 License

MIT — Clean, modern, embeddable.

---

## 🔗 Integration with Ghost Ecosystem

Zsig is designed to be integrated into larger Ghost ecosystem projects:

* **`zwallet`**: Wallet applications can provide their crypto implementation to zsig
* **`zledger`**: Ledger systems can use zsig for transaction signing
* **`ghostforge`**: Build systems can use zsig for artifact signing
* **`ghostmesh`**: Network applications can use zsig for message authentication

### Example Integration

```zig
// In a parent application (e.g., zwallet)
const zcrypto = @import("zcrypto");
const zsig = @import("zsig");

// Provide zcrypto implementation to zsig
const crypto_interface = zsig.CryptoInterface{
    .generateKeypairFn = zcryptoGenerateKeypair,
    .keypairFromSeedFn = zcryptoKeypairFromSeed,
    .signFn = zcryptoSign,
    .verifyFn = zcryptoVerify,
    .hashFn = zcryptoHash,
};

zsig.setCryptoInterface(crypto_interface);
// Now zsig uses zcrypto functions internally
```

