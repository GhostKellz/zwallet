# 🛡️ RealID: Zero-Trust Identity Framework

**RealID** is a secure, portable identity framework built in **Zig**, designed for zero-trust authentication, decentralized identity resolution, and stateless IPv6-based identity. It powers `walletd`, `ghostd`, and other GhostNet Web5 components with cryptographic identity operations and resilient, airgap-compatible tooling.

---

## ✨ Key Features

* 🔑 **Passphrase-based identity** (no seed phrases required)
* 🧾 **Stateless IPv6 QID** generation from public key
* 🔐 **Ed25519-based signature & verification**
* 🌐 **ZNS/ENS/Unstoppable-compatible identity mapping**
* 🔁 **C ABI exports** for Rust, C, or mobile integration
* 📦 **Hardware-friendly**: embedded, container, mobile-safe

---

## 📦 Module Structure

```
realid/
├── src/
│   ├── core.zig         # Keypair generation from passphrase
│   ├── sign.zig         # Ed25519 signing and verification
│   ├── qid.zig          # Stateless IPv6 QID derivation
│   ├── fingerprint.zig  # Optional device identity factor
│   └── ffi.zig          # C ABI interface
├── include/realid.h     # C header file
├── build.zig
└── lib/librealid.a      # Static lib for linking
```

---

## 🔧 Zig API (Internal Use)

```zig
pub fn realid_generate_from_passphrase(pass: []const u8) RealIDKeyPair;
pub fn realid_sign(data: []const u8, key: RealIDPrivateKey) RealIDSignature;
pub fn realid_verify(sig: RealIDSignature, data: []const u8, key: RealIDPublicKey) bool;
pub fn realid_qid_from_pubkey(pubkey: RealIDPublicKey) [16]u8;
```

---

## 🌉 FFI / Integration

### Rust Example

```rust
extern "C" {
  fn realid_sign(data: *const u8, len: usize, key: *const RealIDPrivateKey) -> RealIDSignature;
}
```

Used in `walletd`, `ghostd`, `phantomid`, or `ciphersign` via `librealid.a` or `librealid.so`

---

## 🔐 Identity Model

RealID identities are derived from:

* User passphrase (PBKDF2/SHA3)
* Optional device fingerprint
* Public key → domain mapping (ZNS, ENS, CNS)
* Stateless IPv6 derivation → QID (QUIC Identity)

---

## 📚 Used In

* 🧠 `walletd` → Signing, passphrase auth, RealID-based login
* 👻 `ghostd` → Validator identity, domain-level signature enforcement
* 🌍 `znsd`   → Identity-to-domain resolution and QID-to-name mapping
* 🌐 `ghostsite` → Web5 profile resolution from public key or QID

---

## ✅ Status

* [x] Zig implementation complete
* [x] Ed25519 + QID tested
* [ ] FFI integration examples (in progress)
* [ ] WASM/mobile wrapper (planned)

---

## 📜 License

MIT © GhostKellz

