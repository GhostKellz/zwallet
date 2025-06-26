# ZWallet + RealID + ghostd/walletd Integration Guide

## 🎯 Overview

This document outlines the complete integration between ZWallet (Zig-based secure wallet), RealID (identity management), and the Rust-based ghostd/walletd ecosystem. The integration provides seamless FFI communication and shared functionality.

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   walletd       │    │   ghostd        │    │   Virtual       │
│   (Rust)        │    │   (Rust)        │    │   Machine       │
│                 │    │                 │    │   (Zig/Rust)    │
├─────────────────┤    ├─────────────────┤    ├─────────────────┤
│ Web3 Gateway    │    │ Blockchain Node │    │ Smart Contracts │
│ JSON-RPC API    │    │ P2P Network     │    │ ZVM Runtime     │
│ Account Mgmt    │    │ Consensus       │    │ State Machine   │
└─────────┬───────┘    └─────────┬───────┘    └─────────┬───────┘
          │                      │                      │
          └──────────────────────┼──────────────────────┘
                                 │
                    ┌─────────────┴─────────────┐
                    │      ZWallet FFI         │
                    │      (libzwallet.a)      │
                    ├─────────────────────────────┤
                    │  • Wallet Management      │
                    │  • Transaction Signing    │
                    │  • QID Generation        │
                    │  • RealID Integration    │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │      ZWallet Core        │
                    │         (Zig)           │
                    ├─────────────────────────────┤
                    │ wallet_realid.zig        │
                    │ tx.zig                   │
                    │ qid.zig                  │
                    │ ffi.zig                  │
                    └─────────────┬─────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │       RealID             │
                    │        (Zig)            │
                    ├─────────────────────────────┤
                    │ • Identity Generation    │
                    │ • Ed25519 Signatures     │
                    │ • Device Binding         │
                    │ • QID Derivation         │
                    └─────────────────────────────┘
```

## 🔌 FFI Interface

### C Header Generation

Create `zwallet.h` for Rust integration:

```c
#ifndef ZWALLET_H
#define ZWALLET_H

#include <stdint.h>
#include <stdbool.h>

// Error codes
#define FFI_SUCCESS 0
#define FFI_ERROR_INVALID_PARAM -1
#define FFI_ERROR_WALLET_LOCKED -2
#define FFI_ERROR_INSUFFICIENT_FUNDS -3
#define FFI_ERROR_SIGNING_FAILED -4
#define FFI_ERROR_VERIFICATION_FAILED -5
#define FFI_ERROR_MEMORY_ERROR -6
#define FFI_ERROR_INVALID_ADDRESS -7
#define FFI_ERROR_ACCOUNT_NOT_FOUND -8

// Protocol types
typedef enum {
    PROTOCOL_GHOSTCHAIN = 0,
    PROTOCOL_ETHEREUM = 1,
    PROTOCOL_STELLAR = 2,
    PROTOCOL_HEDERA = 3,
    PROTOCOL_BITCOIN = 4,
} Protocol;

// Key types
typedef enum {
    KEY_TYPE_ED25519 = 0,
    KEY_TYPE_SECP256K1 = 1,
} KeyType;

// Structures
typedef struct {
    void* wallet_ptr;
    void* allocator_ptr;
    bool is_valid;
} ZWalletContext;

typedef struct {
    uint8_t address[64];
    uint32_t address_len;
    uint8_t public_key[32];
    uint8_t qid[16];
    uint32_t protocol;
    uint32_t key_type;
} WalletAccount;

typedef struct {
    void* identity_ptr;
    bool is_valid;
} RealIdContext;

typedef struct {
    uint8_t public_key[32];
    uint8_t qid[16];
    bool device_bound;
} ZidIdentity;

typedef struct {
    uint8_t signature[64];
    bool success;
} SignatureResult;

// ZWallet Functions
extern ZWalletContext zwallet_init(void);
extern void zwallet_destroy(ZWalletContext* ctx);
extern int zwallet_create_wallet(ZWalletContext* ctx, const char* passphrase, uint32_t passphrase_len, 
                                 const char* wallet_name, uint32_t wallet_name_len, bool device_bound);
extern int zwallet_load_wallet(ZWalletContext* ctx, const uint8_t* wallet_data, uint32_t data_len,
                              const char* passphrase, uint32_t passphrase_len);
extern int zwallet_create_account(ZWalletContext* ctx, uint32_t protocol, uint32_t key_type, WalletAccount* account_out);
extern int zwallet_get_balance(ZWalletContext* ctx, uint32_t protocol, const char* token, uint32_t token_len, uint64_t* balance_out);
extern int zwallet_update_balance(ZWalletContext* ctx, uint32_t protocol, const char* token, uint32_t token_len, uint64_t amount, uint8_t decimals);
extern int zwallet_lock(ZWalletContext* ctx);
extern int zwallet_unlock(ZWalletContext* ctx, const char* passphrase, uint32_t passphrase_len);
extern int zwallet_get_master_qid(ZWalletContext* ctx, uint8_t qid_out[16]);

// RealID Functions
extern RealIdContext realid_init(void);
extern void realid_destroy(RealIdContext* ctx);
extern int realid_generate_identity(RealIdContext* ctx, const char* passphrase, uint32_t passphrase_len, 
                                   bool device_bound, ZidIdentity* identity_out);
extern int realid_sign_data(RealIdContext* ctx, const uint8_t* data, uint32_t data_len, SignatureResult* signature_out);
extern bool realid_verify_signature(const uint8_t public_key[32], const uint8_t* data, uint32_t data_len, const uint8_t signature[64]);

// QID Functions
extern int qid_to_string(const uint8_t qid_bytes[16], uint8_t* buffer, uint32_t buffer_len, uint32_t* out_len);
extern int string_to_qid(const char* qid_string, uint32_t string_len, uint8_t qid_out[16]);

#endif // ZWALLET_H
```

### Rust Integration

In `walletd/src/ffi.rs`:

```rust
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};

// Import FFI functions
#[link(name = "zwallet_ffi")]
extern "C" {
    fn zwallet_init() -> ZWalletContext;
    fn zwallet_destroy(ctx: *mut ZWalletContext);
    fn zwallet_create_wallet(
        ctx: *mut ZWalletContext,
        passphrase: *const c_char,
        passphrase_len: u32,
        wallet_name: *const c_char,
        wallet_name_len: u32,
        device_bound: bool,
    ) -> c_int;
    fn zwallet_create_account(
        ctx: *mut ZWalletContext,
        protocol: u32,
        key_type: u32,
        account_out: *mut WalletAccount,
    ) -> c_int;
    fn zwallet_get_balance(
        ctx: *mut ZWalletContext,
        protocol: u32,
        token: *const c_char,
        token_len: u32,
        balance_out: *mut u64,
    ) -> c_int;
    
    fn realid_init() -> RealIdContext;
    fn realid_destroy(ctx: *mut RealIdContext);
    fn realid_generate_identity(
        ctx: *mut RealIdContext,
        passphrase: *const c_char,
        passphrase_len: u32,
        device_bound: bool,
        identity_out: *mut ZidIdentity,
    ) -> c_int;
    fn realid_sign_data(
        ctx: *mut RealIdContext,
        data: *const u8,
        data_len: u32,
        signature_out: *mut SignatureResult,
    ) -> c_int;
    fn realid_verify_signature(
        public_key: *const [u8; 32],
        data: *const u8,
        data_len: u32,
        signature: *const [u8; 64],
    ) -> bool;
}

// Rust structs matching C structs
#[repr(C)]
pub struct ZWalletContext {
    wallet_ptr: *mut std::ffi::c_void,
    allocator_ptr: *mut std::ffi::c_void,
    is_valid: bool,
}

#[repr(C)]
pub struct WalletAccount {
    address: [u8; 64],
    address_len: u32,
    public_key: [u8; 32],
    qid: [u8; 16],
    protocol: u32,
    key_type: u32,
}

#[repr(C)]
pub struct RealIdContext {
    identity_ptr: *mut std::ffi::c_void,
    is_valid: bool,
}

#[repr(C)]
pub struct ZidIdentity {
    public_key: [u8; 32],
    qid: [u8; 16],
    device_bound: bool,
}

#[repr(C)]
pub struct SignatureResult {
    signature: [u8; 64],
    success: bool,
}

// Safe Rust wrapper
pub struct ZWallet {
    context: ZWalletContext,
}

impl ZWallet {
    pub fn new() -> Self {
        let context = unsafe { zwallet_init() };
        Self { context }
    }
    
    pub fn create_wallet(&mut self, passphrase: &str, name: Option<&str>, device_bound: bool) -> Result<(), i32> {
        let passphrase_cstr = CString::new(passphrase).map_err(|_| -1)?;
        let (name_ptr, name_len) = if let Some(n) = name {
            let name_cstr = CString::new(n).map_err(|_| -1)?;
            (name_cstr.as_ptr(), n.len() as u32)
        } else {
            (std::ptr::null(), 0)
        };
        
        let result = unsafe {
            zwallet_create_wallet(
                &mut self.context,
                passphrase_cstr.as_ptr(),
                passphrase.len() as u32,
                name_ptr,
                name_len,
                device_bound,
            )
        };
        
        if result == 0 { Ok(()) } else { Err(result) }
    }
    
    pub fn create_account(&mut self, protocol: u32, key_type: u32) -> Result<WalletAccount, i32> {
        let mut account = WalletAccount {
            address: [0; 64],
            address_len: 0,
            public_key: [0; 32],
            qid: [0; 16],
            protocol: 0,
            key_type: 0,
        };
        
        let result = unsafe {
            zwallet_create_account(&mut self.context, protocol, key_type, &mut account)
        };
        
        if result == 0 { Ok(account) } else { Err(result) }
    }
    
    pub fn get_balance(&mut self, protocol: u32, token: &str) -> Result<u64, i32> {
        let token_cstr = CString::new(token).map_err(|_| -1)?;
        let mut balance = 0u64;
        
        let result = unsafe {
            zwallet_get_balance(
                &mut self.context,
                protocol,
                token_cstr.as_ptr(),
                token.len() as u32,
                &mut balance,
            )
        };
        
        if result == 0 { Ok(balance) } else { Err(result) }
    }
}

impl Drop for ZWallet {
    fn drop(&mut self) {
        unsafe { zwallet_destroy(&mut self.context) };
    }
}

// RealID wrapper
pub struct RealId {
    context: RealIdContext,
}

impl RealId {
    pub fn new() -> Self {
        let context = unsafe { realid_init() };
        Self { context }
    }
    
    pub fn generate_identity(&mut self, passphrase: &str, device_bound: bool) -> Result<ZidIdentity, i32> {
        let passphrase_cstr = CString::new(passphrase).map_err(|_| -1)?;
        let mut identity = ZidIdentity {
            public_key: [0; 32],
            qid: [0; 16],
            device_bound: false,
        };
        
        let result = unsafe {
            realid_generate_identity(
                &mut self.context,
                passphrase_cstr.as_ptr(),
                passphrase.len() as u32,
                device_bound,
                &mut identity,
            )
        };
        
        if result == 0 { Ok(identity) } else { Err(result) }
    }
    
    pub fn sign_data(&mut self, data: &[u8]) -> Result<[u8; 64], i32> {
        let mut signature_result = SignatureResult {
            signature: [0; 64],
            success: false,
        };
        
        let result = unsafe {
            realid_sign_data(
                &mut self.context,
                data.as_ptr(),
                data.len() as u32,
                &mut signature_result,
            )
        };
        
        if result == 0 && signature_result.success {
            Ok(signature_result.signature)
        } else {
            Err(result)
        }
    }
    
    pub fn verify_signature(public_key: &[u8; 32], data: &[u8], signature: &[u8; 64]) -> bool {
        unsafe {
            realid_verify_signature(
                public_key,
                data.as_ptr(),
                data.len() as u32,
                signature,
            )
        }
    }
}

impl Drop for RealId {
    fn drop(&mut self) {
        unsafe { realid_destroy(&mut self.context) };
    }
}
```

## 🚀 Build Integration

### Build Script for Rust

In `walletd/build.rs`:

```rust
use std::env;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let out_dir = env::var("OUT_DIR").unwrap();
    let zwallet_path = "../zwallet"; // Adjust path as needed
    
    // Build ZWallet FFI library
    let output = Command::new("zig")
        .args(&["build", "ffi", "-Doptimize=ReleaseFast"])
        .current_dir(zwallet_path)
        .output()
        .expect("Failed to build ZWallet FFI library");
    
    if !output.status.success() {
        panic!("ZWallet build failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    
    // Copy library to output directory
    let lib_path = format!("{}/zig-out/lib/libzwallet_ffi.a", zwallet_path);
    let dest_path = format!("{}/libzwallet_ffi.a", out_dir);
    std::fs::copy(&lib_path, &dest_path)
        .expect("Failed to copy ZWallet library");
    
    // Link the library
    println!("cargo:rustc-link-lib=static=zwallet_ffi");
    println!("cargo:rustc-link-search=native={}", out_dir);
    
    // Re-run if ZWallet source changes
    println!("cargo:rerun-if-changed={}/src", zwallet_path);
}
```

### Cargo.toml Dependencies

In `walletd/Cargo.toml`:

```toml
[package]
name = "walletd"
version = "0.1.0"
edition = "2021"
build = "build.rs"

[dependencies]
tokio = { version = "1.0", features = ["full"] }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
hex = "0.4"
# ... other dependencies

[build-dependencies]
# ... build dependencies
```

## 🔧 Usage Examples

### walletd Integration

```rust
// In walletd/src/wallet.rs
use crate::ffi::{ZWallet, RealId};

pub struct WalletService {
    zwallet: ZWallet,
    realid: RealId,
}

impl WalletService {
    pub fn new() -> Self {
        Self {
            zwallet: ZWallet::new(),
            realid: RealId::new(),
        }
    }
    
    pub async fn create_wallet(&mut self, passphrase: &str, device_bound: bool) -> Result<String, Box<dyn std::error::Error>> {
        // Create RealID identity
        let identity = self.realid.generate_identity(passphrase, device_bound)?;
        
        // Create ZWallet
        self.zwallet.create_wallet(passphrase, Some("walletd"), device_bound)?;
        
        // Create GhostChain account
        let account = self.zwallet.create_account(0, 0)?; // GhostChain, Ed25519
        
        // Format QID as string
        let qid_str = format!("{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}:{:02x}{:02x}",
            identity.qid[0], identity.qid[1], identity.qid[2], identity.qid[3],
            identity.qid[4], identity.qid[5], identity.qid[6], identity.qid[7],
            identity.qid[8], identity.qid[9], identity.qid[10], identity.qid[11],
            identity.qid[12], identity.qid[13], identity.qid[14], identity.qid[15]);
        
        Ok(qid_str)
    }
    
    pub async fn sign_transaction(&mut self, transaction_data: &[u8]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let signature = self.realid.sign_data(transaction_data)?;
        Ok(signature.to_vec())
    }
    
    pub async fn verify_transaction(&self, public_key: &[u8; 32], transaction_data: &[u8], signature: &[u8; 64]) -> bool {
        RealId::verify_signature(public_key, transaction_data, signature)
    }
    
    pub async fn get_balance(&mut self, protocol: u32, token: &str) -> Result<u64, Box<dyn std::error::Error>> {
        let balance = self.zwallet.get_balance(protocol, token)?;
        Ok(balance)
    }
}
```

### ghostd Integration

```rust
// In ghostd/src/node.rs
use crate::wallet::WalletService;

pub struct GhostNode {
    wallet_service: WalletService,
    // ... other node components
}

impl GhostNode {
    pub fn new() -> Self {
        Self {
            wallet_service: WalletService::new(),
            // ... initialize other components
        }
    }
    
    pub async fn process_transaction(&mut self, tx_data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        // Sign transaction with integrated wallet
        let signature = self.wallet_service.sign_transaction(tx_data).await?;
        
        // Broadcast to network
        // ... network logic
        
        Ok(hex::encode(signature))
    }
    
    pub async fn create_node_identity(&mut self, passphrase: &str) -> Result<String, Box<dyn std::error::Error>> {
        // Create device-bound identity for the node
        let qid = self.wallet_service.create_wallet(passphrase, true).await?;
        
        println!("Node identity created with QID: {}", qid);
        Ok(qid)
    }
}
```

## 🧪 Testing Integration

### Zig Tests

```bash
# Build and test ZWallet with RealID
zig build test

# Test FFI interface
zig build test --test-filter "FFI"

# Build RealID CLI example
zig build realid-cli

# Test RealID CLI
./zig-out/bin/zwallet_realid_cli create --passphrase "test123" --device-bound
./zig-out/bin/zwallet_realid_cli account --protocol ghostchain --keytype ed25519
./zig-out/bin/zwallet_realid_cli qid
```

### Rust Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_wallet_integration() {
        let mut wallet_service = WalletService::new();
        
        // Create wallet
        let qid = wallet_service.create_wallet("test_passphrase", false).await.unwrap();
        assert!(!qid.is_empty());
        
        // Test balance
        let balance = wallet_service.get_balance(0, "gcc").await.unwrap();
        assert_eq!(balance, 0); // Initial balance
        
        // Test signing
        let test_data = b"Hello, GhostNet!";
        let signature = wallet_service.sign_transaction(test_data).await.unwrap();
        assert_eq!(signature.len(), 64);
    }
    
    #[test]
    fn test_realid_integration() {
        let mut realid = RealId::new();
        
        // Generate identity
        let identity = realid.generate_identity("test_phrase", false).unwrap();
        assert!(!identity.device_bound);
        
        // Sign and verify
        let data = b"test message";
        let signature = realid.sign_data(data).unwrap();
        let is_valid = RealId::verify_signature(&identity.public_key, data, &signature);
        assert!(is_valid);
    }
}
```

## 🔮 Future Enhancements

### ZVM Integration

```zig
// Future ZVM integration in zwallet
pub const ZVMIntegration = struct {
    pub fn executeContract(self: *Wallet, contract_code: []const u8, input: []const u8) ![]const u8 {
        // Execute smart contract with wallet context
        // Sign contract calls with RealID
        // Return execution result
    }
    
    pub fn deployContract(self: *Wallet, bytecode: []const u8) ![]const u8 {
        // Deploy contract with wallet as deployer
        // Use QID for contract addressing
        // Return deployed contract address
    }
};
```

### Performance Optimizations

1. **Connection Pooling**: Reuse FFI contexts for multiple operations
2. **Batch Operations**: Group multiple wallet operations
3. **Async Support**: Non-blocking FFI calls where possible
4. **Memory Management**: Efficient allocation and cleanup

### Security Enhancements

1. **Hardware Security**: Integration with hardware wallets
2. **Multi-signature**: Threshold signatures with RealID
3. **Audit Logging**: Comprehensive operation logging
4. **Zero-knowledge**: Privacy-preserving transactions

This integration provides a complete, production-ready bridge between the Zig-based ZWallet/RealID system and the Rust-based ghostd/walletd ecosystem, enabling seamless interoperability and shared security features.
