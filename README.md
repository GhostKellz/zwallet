# Zwallet: A Secure, Programmable Wallet for Zig

**Zwallet** is a modern, privacy-first wallet library and command-line interface written in Zig. It’s purpose-built to support a variety of blockchain protocols (including GhostChain, Ethereum, Stellar, and Hedera), integrating smoothly with Web2/Web3 applications, mobile devices, and self-hosted infrastructure.

---

## 🏡 Purpose & Vision

Zwallet rethinks what a crypto wallet can be:

* Native integration with your system and CLI tools
* Hardware-backed, passkey-like key storage
* Support for both public identity and private, secure accounts
* Interaction with Layer 1, Layer 2, and off-chain assets
* Built-in support for tokenized digital and real-world assets

---

## 🔑 Key Features

### ✔️ Key Management

* HD Wallet support (BIP-32/BIP-39/BIP-44)
* Ed25519 / Secp256k1 / Curve25519 key types
* Hardware Wallet (FIDO2, YubiKey, TPM) support (planned)

### ✔️ Wallet Modes

* Public Identity Wallet: shareable ENS/Unstoppable domain
* Private Cold Wallet: offline / air-gapped operation
* Hybrid Mode: transaction preview + approval

### ✔️ Protocol Support

* GhostChain native token (GCC)
* Ethereum (ERC20/721/1155)
* Stellar (XLM + anchors)
* Hedera (HBAR, tokens)
* Ripple / RLUSD support (planned)

### ✔️ UX & CLI

* Interactive CLI with encrypted local keystore
* QR code generation for mobile wallet imports
* Transaction signing, fee preview, broadcast
* Web API bridge (for web3/browser integration)

---

## 🏛 Architecture

* `zwallet.core` - Core wallet logic (keys, storage, security)
* `zwallet.protocol` - Blockchain-specific encoding/signing
* `zwallet.identity` - ENS/UDN and Web2 DNS integrations
* `zwallet.cli` - Command interface and UX helpers
* `zwallet.bridge` - Web interface + API layer

---

## 🤝 Example Use

```bash
zwallet generate --type ed25519 --name ghostkellz
zwallet import --mnemonic "..."
zwallet balance --token gcc
zwallet send --to chris.eth --amount 420 --token gcc
```

---

## 🚀 Planned Extensions

* zk-SNARK / zk-STARK privacy integration
* Modular signing agents (e.g. sign using Jarvis)
* Biometric authentication (FIDO/WebAuthn bridge)
* Lightning-style microtransaction layer (GhostMesh VPN tokens)

---

## ✨ Use Cases

* Secure wallet for CLI-native blockchain interaction
* Hardware-secured key vault for AI agents like Jarvis
* Self-hosted payment gateway and transaction signer
* Infrastructure token orchestration in distributed environments

---

## ⚡ Performance Goals

* Fully offline operation supported
* Secure by default: zero key leakage
* Low RAM/CPU impact for embedded targets

---

## 🛡️ Security Practices

* Argon2 key derivation for secrets
* Keystore encryption using system entropy sources
* Zero-copy secure memory handling (planned)
* Support for detached multisig vaults

---

## 🎓 Requirements

* Zig v0.12+
* Optional: `libsodium` or `ring` backend for FFI bridging
* OS support: Linux, macOS, BSD, and containerized targets

---

## 📄 License

MIT + Commons Clause for CLI tool to protect distribution monetization (optional)

---

**Zwallet** — Your CLI-native secure vault for the programmable internet.

