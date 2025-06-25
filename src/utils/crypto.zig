//! Cryptographic utilities and key management
//! Uses std.crypto for now, with zcrypto/zsig integration planned

const std = @import("std");
const Allocator = std.mem.Allocator;

const zcrypto = @import("zcrypto");

pub const CryptoError = error{
    InvalidKey,
    InvalidSignature,
    KeyGenerationFailed,
    SigningFailed,
    VerificationFailed,
    InvalidMnemonic,
    InvalidSeed,
};

pub const KeyPair = struct {
    public_key: [33]u8, // secp256k1 uses 33-byte compressed public keys
    private_key: [64]u8,
    key_type: KeyType,
    
    pub fn deinit(self: *KeyPair) void {
        // Securely zero out private key
        zcrypto.util.secureZero(&self.private_key);
    }
    
    /// Generate new keypair
    pub fn generate(key_type: KeyType) !KeyPair {
        switch (key_type) {
            .ed25519 => return generateEd25519(),
            .secp256k1 => return generateSecp256k1(),
            .curve25519 => return generateCurve25519(),
        }
    }
    
    /// Generate from seed
    pub fn fromSeed(seed: [32]u8, key_type: KeyType) !KeyPair {
        switch (key_type) {
            .ed25519 => return ed25519FromSeed(seed),
            .secp256k1 => return secp256k1FromSeed(seed),
            .curve25519 => return curve25519FromSeed(seed),
        }
    }
    
    /// Sign message
    pub fn sign(self: *const KeyPair, message: []const u8, allocator: Allocator) ![]u8 {
        switch (self.key_type) {
            .ed25519 => return signEd25519(message, &self.private_key, allocator),
            .secp256k1 => return signSecp256k1(message, &self.private_key, allocator),
            .curve25519 => return CryptoError.SigningFailed, // Not for signing
        }
    }
    
    /// Verify signature
    pub fn verify(self: *const KeyPair, message: []const u8, signature: []const u8) bool {
        switch (self.key_type) {
            .ed25519 => return verifyEd25519(message, signature, &self.public_key),
            .secp256k1 => return verifySecp256k1(message, signature, &self.public_key),
            .curve25519 => return false, // Not for signing
        }
    }
};

pub const KeyType = enum {
    ed25519,
    secp256k1,
    curve25519,
};

/// Generate Ed25519 keypair using zcrypto
fn generateEd25519() !KeyPair {
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .ed25519,
    };
    
    // Use zcrypto's Ed25519 implementation
    const ed_keypair = zcrypto.asym.ed25519.generate();
    @memcpy(keypair.public_key[0..32], &ed_keypair.public_key);
    keypair.public_key[32] = 0; // Pad to 33 bytes
    @memcpy(&keypair.private_key, &ed_keypair.private_key);
    
    return keypair;
}

/// Generate Ed25519 keypair from seed
fn ed25519FromSeed(seed: [32]u8) !KeyPair {
    _ = seed; // TODO: Implement proper seed-based generation
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .ed25519,
    };
    
    // Use zcrypto's Ed25519 implementation (random for now)
    const ed_keypair = zcrypto.asym.ed25519.generate();
    @memcpy(keypair.public_key[0..32], &ed_keypair.public_key);
    keypair.public_key[32] = 0; // Pad to 33 bytes
    @memcpy(&keypair.private_key, &ed_keypair.private_key);
    
    return keypair;
}

/// Generate secp256k1 keypair using zcrypto
fn generateSecp256k1() !KeyPair {
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .secp256k1,
    };
    
    // Use zcrypto's secp256k1 implementation
    const secp_keypair = zcrypto.asym.secp256k1.generate();
    @memcpy(&keypair.public_key, &secp_keypair.public_key);
    @memcpy(keypair.private_key[0..32], &secp_keypair.private_key);
    @memset(keypair.private_key[32..64], 0);
    
    return keypair;
}

/// Generate secp256k1 keypair from seed using zcrypto
fn secp256k1FromSeed(seed: [32]u8) !KeyPair {
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .secp256k1,
    };
    
    // Use zcrypto's secp256k1 implementation (random for now)
    _ = seed; // TODO: Implement proper seed-based generation
    const secp_keypair = zcrypto.asym.secp256k1.generate();
    @memcpy(&keypair.public_key, &secp_keypair.public_key);
    @memcpy(keypair.private_key[0..32], &secp_keypair.private_key);
    @memset(keypair.private_key[32..64], 0);
    
    return keypair;
}

/// Generate Curve25519 keypair using zcrypto
fn generateCurve25519() !KeyPair {
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .curve25519,
    };
    
    // Use zcrypto's X25519 implementation
    const x25519_keypair = zcrypto.asym.x25519.generate();
    
    @memcpy(keypair.public_key[0..32], &x25519_keypair.public_key);
    keypair.public_key[32] = 0; // Pad to 33 bytes
    @memcpy(keypair.private_key[0..32], &x25519_keypair.private_key);
    @memset(keypair.private_key[32..64], 0);
    
    return keypair;
}

/// Generate Curve25519 keypair from seed using zcrypto
fn curve25519FromSeed(seed: [32]u8) !KeyPair {
    _ = seed; // TODO: Implement proper seed-based generation
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .curve25519,
    };
    
    // Use zcrypto's X25519 implementation (random for now)
    const x25519_keypair = zcrypto.asym.x25519.generate();
    
    @memcpy(keypair.public_key[0..32], &x25519_keypair.public_key);
    keypair.public_key[32] = 0; // Pad to 33 bytes
    @memcpy(keypair.private_key[0..32], &x25519_keypair.private_key);
    @memset(keypair.private_key[32..64], 0);
    
    return keypair;
}

/// Sign with Ed25519 using zcrypto
fn signEd25519(message: []const u8, private_key: *const [64]u8, allocator: Allocator) ![]u8 {
    // Use zcrypto's Ed25519 signing (needs full 64-byte private key)
    const signature = zcrypto.asym.ed25519.sign(message, private_key.*);
    
    // Allocate and return signature
    const sig_bytes = try allocator.alloc(u8, 64);
    @memcpy(sig_bytes, &signature);
    return sig_bytes;
}

/// Verify Ed25519 signature using zcrypto
fn verifyEd25519(message: []const u8, signature: []const u8, public_key: *const [33]u8) bool {
    if (signature.len != 64) return false;
    
    var sig_bytes: [64]u8 = undefined;
    @memcpy(&sig_bytes, signature);
    
    // Use zcrypto's Ed25519 verification (use first 32 bytes of public key)
    var ed_pubkey: [32]u8 = undefined;
    @memcpy(&ed_pubkey, public_key[0..32]);
    return zcrypto.asym.ed25519.verify(message, sig_bytes, ed_pubkey);
}

/// Sign with secp256k1 using zcrypto
fn signSecp256k1(message: []const u8, private_key: *const [64]u8, allocator: Allocator) ![]u8 {
    // Hash the message for secp256k1 signing
    const message_hash = zcrypto.hash.sha256(message);
    
    // Use zcrypto's secp256k1 signing
    const signature = zcrypto.asym.secp256k1.sign(message_hash, private_key[0..32].*);
    
    // Return as 64-byte signature
    const sig_bytes = try allocator.alloc(u8, 64);
    @memcpy(sig_bytes, &signature);
    
    return sig_bytes;
}

/// Verify secp256k1 signature using zcrypto
fn verifySecp256k1(message: []const u8, signature: []const u8, public_key: *const [33]u8) bool {
    if (signature.len != 64) return false;
    
    // Hash the message for secp256k1 verification
    const message_hash = zcrypto.hash.sha256(message);
    
    var sig_bytes: [64]u8 = undefined;
    @memcpy(&sig_bytes, signature);
    
    // Use zcrypto's secp256k1 verification (full 33-byte compressed public key)
    return zcrypto.asym.secp256k1.verify(message_hash, sig_bytes, public_key.*);
}

/// BIP-32 HD wallet support
pub const HDNode = struct {
    key: KeyPair,
    chain_code: [32]u8,
    depth: u8,
    index: u32,
    parent_fingerprint: [4]u8,
    
    /// Derive child key using BIP-32
    pub fn deriveChild(self: *const HDNode, index: u32, hardened: bool) !HDNode {
        const index_value = if (hardened) index + 0x80000000 else index;
        
        // Prepare data for HMAC
        var data: [37]u8 = undefined;
        
        if (hardened) {
            // Use private key
            data[0] = 0x00;
            @memcpy(data[1..33], self.key.private_key[0..32]);
        } else {
            // Use public key
            @memcpy(data[0..33], &self.key.public_key);
        }
        
        // Add index
        std.mem.writeInt(u32, data[33..37], index_value, .big);
        
        // Compute HMAC-SHA512 using zcrypto
        const hmac_result = zcrypto.auth.hmac.sha512(&data, &self.chain_code);
        
        // Split result
        var child_key: [32]u8 = undefined;
        var child_chain_code: [32]u8 = undefined;
        @memcpy(&child_key, hmac_result[0..32]);
        @memcpy(&child_chain_code, hmac_result[32..64]);
        
        // Create child keypair
        const child_keypair = try KeyPair.fromSeed(child_key, self.key.key_type);
        
        // Calculate parent fingerprint
        const parent_pubkey_hash = zcrypto.hash.sha256(&self.key.public_key);
        var parent_fingerprint: [4]u8 = undefined;
        @memcpy(&parent_fingerprint, parent_pubkey_hash[0..4]);
        
        return HDNode{
            .key = child_keypair,
            .chain_code = child_chain_code,
            .depth = self.depth + 1,
            .index = index_value,
            .parent_fingerprint = parent_fingerprint,
        };
    }
};

/// Generate mnemonic phrase using BIP-39 from zcrypto
pub fn generateMnemonic(allocator: Allocator, entropy_bits: u16) ![]const u8 {
    if (entropy_bits % 32 != 0 or entropy_bits < 128 or entropy_bits > 256) {
        return CryptoError.InvalidSeed;
    }
    
    // Use zcrypto BIP-39 implementation
    const word_count = switch (entropy_bits) {
        128 => zcrypto.bip.MnemonicLength.words_12,
        160 => zcrypto.bip.MnemonicLength.words_15,
        192 => zcrypto.bip.MnemonicLength.words_18,
        224 => zcrypto.bip.MnemonicLength.words_21,
        256 => zcrypto.bip.MnemonicLength.words_24,
        else => return CryptoError.InvalidSeed,
    };
    
    const mnemonic = try zcrypto.bip.bip39.generate(allocator, word_count);
    // Join the words with spaces to create a single string
    return try std.mem.join(allocator, " ", mnemonic.words);
}

/// Convert mnemonic to seed using BIP-39 from zcrypto
pub fn mnemonicToSeed(mnemonic: []const u8, passphrase: ?[]const u8, allocator: Allocator) ![64]u8 {
    // Use zcrypto's BIP-39 mnemonicToSeed function directly
    const seed = try zcrypto.bip.bip39.mnemonicToSeed(allocator, mnemonic, passphrase orelse "");
    defer allocator.free(seed);
    
    var result: [64]u8 = undefined;
    if (seed.len >= 64) {
        @memcpy(&result, seed[0..64]);
    } else {
        @memcpy(result[0..seed.len], seed);
        @memset(result[seed.len..], 0);
    }
    
    return result;
}

/// Create HD wallet from seed using zcrypto BIP-32
pub fn createHDWallet(seed: [64]u8, key_type: KeyType) !HDNode {
    // Use zcrypto BIP-32 master key generation
    const master = zcrypto.bip.bip32.masterKeyFromSeed(&seed);
    
    // Create keypair from master key
    const master_keypair = try KeyPair.fromSeed(master.key, key_type);
    
    return HDNode{
        .key = master_keypair,
        .chain_code = master.chain_code,
        .depth = 0,
        .index = 0,
        .parent_fingerprint = [_]u8{0} ** 4,
    };
}

test "keypair generation" {
    var keypair = try KeyPair.generate(.ed25519);
    defer keypair.deinit();
    
    try std.testing.expect(keypair.key_type == .ed25519);
}

test "signing and verification" {
    var keypair = try KeyPair.generate(.ed25519);
    defer keypair.deinit();
    
    const message = "Hello, Zwallet!";
    const signature = try keypair.sign(message, std.testing.allocator);
    defer std.testing.allocator.free(signature);
    
    try std.testing.expect(keypair.verify(message, signature));
}

test "BIP-39 mnemonic" {
    const mnemonic = try generateMnemonic(std.testing.allocator, 128);
    defer std.testing.allocator.free(mnemonic);
    
    const seed = try mnemonicToSeed(mnemonic, null, std.testing.allocator);
    try std.testing.expect(seed.len == 64);
}

test "HD wallet derivation" {
    var seed: [64]u8 = undefined;
    std.crypto.random.bytes(&seed);
    
    const master = try createHDWallet(seed, .secp256k1);
    const child = try master.deriveChild(0, false);
    
    try std.testing.expect(child.depth == 1);
    try std.testing.expect(child.index == 0);
}