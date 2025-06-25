# Zsig: Cryptographic Signing Engine for Zig

## 📌 Overview

**Zsig** is a lightweight and modular cryptographic signing library written in Zig. Designed for fast, secure, and minimalistic digital signature operations, Zsig powers components like `zledger`, `zwallet`, and other blockchain or secure communication tools.

It uses **Ed25519** signatures as its core primitive, with a focus on deterministic signing, auditability, and WASM compatibility.

---

## 🎯 Goals

* 🔐 Provide fast, minimal Ed25519 signing & verification
* 🧱 Zig-native: No external C dependencies
* 🪶 WASM, CLI, and embedded-friendly
* 🔁 Stateless signing workflows for audit trails
* 🔌 Pluggable for other Zig cryptographic backends

---

## 🔧 Features

* ✅ Ed25519 signing
* ✅ Public/private keypair generation
* ✅ Detached or inline signatures
* ✅ Signature verification API
* ✅ CLI signer + key manager
* ✅ Optional deterministic keygen (brain wallets/passphrases)

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

## 🔗 Related Projects

* [`zledger`](./zledger.md)
* [`zwallet`](./zwallet.md)
* [`zcrypto`](./zcrypto.md)
* [`ghostforge`](https://github.com/ghostkellz/ghostforge)
* [`ghostmesh`](./ghostmesh.md)

