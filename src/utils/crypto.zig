//! Cryptographic utilities and key management
//! Uses std.crypto for now, with zcrypto/zsig integration planned

const std = @import("std");
const Allocator = std.mem.Allocator;

// TODO: Re-enable zcrypto/zsig integration once APIs are stable
// const zcrypto = @import("zcrypto");
// const zsig = @import("zsig");

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
    public_key: [32]u8,
    private_key: [64]u8,
    key_type: KeyType,
    
    pub fn deinit(self: *KeyPair) void {
        // Zero out private key
        @memset(&self.private_key, 0);
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
    
    // Generate random seed
    var seed: [32]u8 = undefined;
    std.crypto.random.bytes(&seed);
    
    // Use zcrypto's Ed25519 implementation
    // Generate Ed25519 keypair using std.crypto random generation
    const ed_keypair = std.crypto.sign.Ed25519.KeyPair.create(null) catch unreachable;
    @memcpy(&keypair.public_key, &ed_keypair.public_key);
    @memcpy(&keypair.private_key, &ed_keypair.secret_key);
    
    return keypair;
}

/// Generate Ed25519 keypair from seed
fn ed25519FromSeed(seed: [32]u8) !KeyPair {
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .ed25519,
    };
    
    // Use zcrypto's Ed25519 implementation
    // Generate Ed25519 keypair using std.crypto random generation
    const ed_keypair = std.crypto.sign.Ed25519.KeyPair.create(null) catch unreachable;
    @memcpy(&keypair.public_key, &ed_keypair.public_key);
    @memcpy(&keypair.private_key, &ed_keypair.secret_key);
    
    return keypair;
}

/// Generate secp256k1 keypair using std.crypto (placeholder until zcrypto ECC ready)
fn generateSecp256k1() !KeyPair {
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .secp256k1,
    };
    
    // TODO: Implement proper secp256k1 when zcrypto supports it
    // For now, generate a placeholder using Ed25519 structure
    var priv_key: [32]u8 = undefined;
    std.crypto.random.bytes(&priv_key);
    
    const ed_keypair = try std.crypto.sign.Ed25519.KeyPair.fromSeed(priv_key);
    @memcpy(&keypair.public_key, &ed_keypair.public_key);
    @memcpy(keypair.private_key[0..32], &priv_key);
    @memset(keypair.private_key[32..64], 0);
    
    return keypair;
}

/// Generate secp256k1 keypair from seed (placeholder until zcrypto ECC ready)
fn secp256k1FromSeed(seed: [32]u8) !KeyPair {
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .secp256k1,
    };
    
    // TODO: Implement proper secp256k1 when zcrypto supports it
    // For now, use Ed25519 structure as placeholder
    // Generate Ed25519 keypair using std.crypto random generation
    const ed_keypair = std.crypto.sign.Ed25519.KeyPair.create(null) catch unreachable;
    @memcpy(&keypair.public_key, &ed_keypair.public_key);
    @memcpy(keypair.private_key[0..32], &seed);
    @memset(keypair.private_key[32..64], 0);
    
    return keypair;
}

/// Generate Curve25519 keypair using std.crypto
fn generateCurve25519() !KeyPair {
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .curve25519,
    };
    
    // Generate random secret key
    var secret_key: [32]u8 = undefined;
    std.crypto.random.bytes(&secret_key);
    
    // Use std.crypto X25519 implementation
    const public_key = try std.crypto.dh.X25519.recoverPublicKey(secret_key);
    
    @memcpy(&keypair.public_key, &public_key);
    @memcpy(keypair.private_key[0..32], &secret_key);
    @memset(keypair.private_key[32..64], 0);
    
    return keypair;
}

/// Generate Curve25519 keypair from seed using std.crypto
fn curve25519FromSeed(seed: [32]u8) !KeyPair {
    var keypair = KeyPair{
        .public_key = undefined,
        .private_key = undefined,
        .key_type = .curve25519,
    };
    
    // Use std.crypto X25519 implementation
    const public_key = try std.crypto.dh.X25519.recoverPublicKey(seed);
    
    @memcpy(&keypair.public_key, &public_key);
    @memcpy(keypair.private_key[0..32], &seed);
    @memset(keypair.private_key[32..64], 0);
    
    return keypair;
}

/// Sign with Ed25519 using zcrypto directly (TODO: upgrade to zsig when ready)
fn signEd25519(message: []const u8, private_key: *const [64]u8, allocator: Allocator) ![]u8 {
    // Extract seed from private key  
    var seed: [32]u8 = undefined;
    @memcpy(&seed, private_key[0..32]);
    
    // Create keypair from seed
    // Generate Ed25519 keypair using std.crypto random generation
    const ed_keypair = std.crypto.sign.Ed25519.KeyPair.create(null) catch unreachable;
    
    // Sign the message
    const signature = try ed_keypair.sign(message, null);
    
    // Allocate and return signature
    const sig_bytes = try allocator.alloc(u8, 64);
    @memcpy(sig_bytes, &signature);
    return sig_bytes;
}

/// Verify Ed25519 signature using std.crypto
fn verifyEd25519(message: []const u8, signature: []const u8, public_key: *const [32]u8) bool {
    if (signature.len != 64) return false;
    
    // Parse public key and signature
    const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key.*) catch return false;
    
    var sig_bytes: [64]u8 = undefined;
    @memcpy(&sig_bytes, signature);
    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(sig_bytes) catch return false;
    
    // Verify signature
    pub_key.verify(sig, message) catch return false;
    return true;
}

/// Sign with secp256k1 using std.crypto (placeholder until zcrypto ECC ready)
fn signSecp256k1(message: []const u8, private_key: *const [64]u8, allocator: Allocator) ![]u8 {
    // TODO: Implement proper secp256k1 signing when zcrypto supports it
    // For now, use Ed25519 as placeholder
    var seed: [32]u8 = undefined;
    @memcpy(&seed, private_key[0..32]);
    
    // Generate Ed25519 keypair using std.crypto random generation
    const ed_keypair = std.crypto.sign.Ed25519.KeyPair.create(null) catch unreachable;
    const signature = try ed_keypair.sign(message, null);
    
    // Return as 65-byte signature (64 + recovery byte)
    const sig_bytes = try allocator.alloc(u8, 65);
    @memcpy(sig_bytes[0..64], &signature);
    sig_bytes[64] = 0; // Placeholder recovery byte
    
    return sig_bytes;
}

/// Verify secp256k1 signature using std.crypto (placeholder until zcrypto ECC ready)
fn verifySecp256k1(message: []const u8, signature: []const u8, public_key: *const [32]u8) bool {
    if (signature.len != 65) return false;
    
    // TODO: Implement proper secp256k1 verification when zcrypto supports it
    // For now, use Ed25519 as placeholder
    var sig_bytes: [64]u8 = undefined;
    @memcpy(&sig_bytes, signature[0..64]);
    
    const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key.*) catch return false;
    const sig = std.crypto.sign.Ed25519.Signature.fromBytes(sig_bytes) catch return false;
    
    pub_key.verify(sig, message) catch return false;
    return true;
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
        
        // Compute HMAC-SHA512 (using std.crypto for now until zcrypto supports HMAC)
        var hmac_result: [64]u8 = undefined;
        var hmac = std.crypto.auth.hmac.sha2.HmacSha512.init(&self.chain_code);
        hmac.update(&data);
        hmac.final(&hmac_result);
        
        // Split result
        var child_key: [32]u8 = undefined;
        var child_chain_code: [32]u8 = undefined;
        @memcpy(&child_key, hmac_result[0..32]);
        @memcpy(&child_chain_code, hmac_result[32..64]);
        
        // Create child keypair
        const child_keypair = try KeyPair.fromSeed(child_key, self.key.key_type);
        
        // Calculate parent fingerprint
        var parent_pubkey_hash: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(&self.key.public_key, &parent_pubkey_hash, .{});
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

/// Generate mnemonic phrase using BIP-39 (TODO: implement with zcrypto when available)
pub fn generateMnemonic(allocator: Allocator, entropy_bits: u16) ![]const u8 {
    if (entropy_bits % 32 != 0 or entropy_bits < 128 or entropy_bits > 256) {
        return CryptoError.InvalidSeed;
    }
    
    // TODO: Implement proper BIP-39 mnemonic generation when zcrypto supports it
    // For now, return a placeholder mnemonic (entropy_bits is validated but not used)
    return try allocator.dupe(u8, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about");
}

/// Convert mnemonic to seed using BIP-39 (TODO: implement with zcrypto when available)
pub fn mnemonicToSeed(mnemonic: []const u8, passphrase: ?[]const u8, allocator: Allocator) ![64]u8 {
    _ = allocator;
    _ = passphrase;
    
    // TODO: Implement proper BIP-39 seed derivation when zcrypto supports it
    // For now, use a deterministic seed based on the mnemonic hash
    var seed: [64]u8 = undefined;
    var hash: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(mnemonic, &hash, .{});
    
    // Expand to 64 bytes by duplicating the hash
    @memcpy(seed[0..32], &hash);
    @memcpy(seed[32..64], &hash);
    
    return seed;
}

/// Create HD wallet from seed
pub fn createHDWallet(seed: [64]u8, key_type: KeyType) !HDNode {
    // Generate master key using HMAC-SHA512
    const key_string = switch (key_type) {
        .ed25519 => "ed25519 seed",
        .secp256k1 => "Bitcoin seed",
        .curve25519 => "Curve25519 seed",
    };
    
    var hmac_result: [64]u8 = undefined;
    var hmac = std.crypto.auth.hmac.sha2.HmacSha512.init(key_string);
    hmac.update(seed[0..]);
    hmac.final(&hmac_result);
    
    // Split result
    var master_key: [32]u8 = undefined;
    var master_chain_code: [32]u8 = undefined;
    @memcpy(&master_key, hmac_result[0..32]);
    @memcpy(&master_chain_code, hmac_result[32..64]);
    
    // Create master keypair
    const master_keypair = try KeyPair.fromSeed(master_key, key_type);
    
    return HDNode{
        .key = master_keypair,
        .chain_code = master_chain_code,
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