//! Crypto backend system for zsig
//! Supports multiple backends: std.crypto and zcrypto v0.3.0

const std = @import("std");

// Import zcrypto if available
const zcrypto = @import("zcrypto");

pub const PUBLIC_KEY_SIZE = 32;
pub const PRIVATE_KEY_SIZE = 64;
pub const SIGNATURE_SIZE = 64;
pub const SEED_SIZE = 32;

/// Backend types
pub const Backend = enum {
    std_crypto,
    zcrypto,
    
    pub const default = Backend.zcrypto; // Use zcrypto v0.3.0 as default
};

/// Crypto backend interface
pub const CryptoInterface = struct {
    generateKeypairFn: *const fn (std.mem.Allocator) anyerror!Keypair,
    keypairFromSeedFn: *const fn ([SEED_SIZE]u8) Keypair,
    signFn: *const fn ([]const u8, Keypair) anyerror!Signature,
    verifyFn: *const fn ([]const u8, [SIGNATURE_SIZE]u8, [PUBLIC_KEY_SIZE]u8) bool,
    signWithContextFn: *const fn ([]const u8, []const u8, Keypair) anyerror!Signature,
    verifyWithContextFn: *const fn ([]const u8, []const u8, [SIGNATURE_SIZE]u8, [PUBLIC_KEY_SIZE]u8) bool,
};

/// Unified keypair structure
pub const Keypair = struct {
    public_key: [PUBLIC_KEY_SIZE]u8,
    private_key: [PRIVATE_KEY_SIZE]u8,
    
    pub fn publicKey(self: Keypair) [PUBLIC_KEY_SIZE]u8 {
        return self.public_key;
    }
    
    pub fn privateKey(self: Keypair) [PRIVATE_KEY_SIZE]u8 {
        return self.private_key;
    }
    
    /// Sign a message with this keypair
    pub fn sign(self: Keypair, message: []const u8) ![SIGNATURE_SIZE]u8 {
        const signature = try getBackend().signFn(message, self);
        return signature.bytes;
    }
    
    /// Sign a message with context
    pub fn signWithContext(self: Keypair, message: []const u8, context: []const u8) ![SIGNATURE_SIZE]u8 {
        const signature = try getBackend().signWithContextFn(message, context, self);
        return signature.bytes;
    }
    
    /// Static method for generating new keypair
    pub fn generate(allocator: std.mem.Allocator) !Keypair {
        return generateKeypair(allocator);
    }
    
    /// Static method for creating keypair from seed
    pub fn fromSeed(seed: [SEED_SIZE]u8) Keypair {
        return keypairFromSeed(seed);
    }
};

/// Signature structure
pub const Signature = struct {
    bytes: [SIGNATURE_SIZE]u8,
    
    pub fn toHex(self: Signature, allocator: std.mem.Allocator) ![]u8 {
        return std.fmt.allocPrint(allocator, "{}", .{std.fmt.fmtSliceHexLower(&self.bytes)});
    }
    
    pub fn toBase64(self: Signature, allocator: std.mem.Allocator) ![]u8 {
        const encoder = std.base64.standard.Encoder;
        const encoded_len = encoder.calcSize(self.bytes.len);
        const result = try allocator.alloc(u8, encoded_len);
        _ = encoder.encode(result, &self.bytes);
        return result;
    }
};

/// Current backend interface
var current_backend: CryptoInterface = undefined;
var backend_initialized: bool = false;

/// Initialize the backend system
pub fn init() void {
    if (!backend_initialized) {
        current_backend = ZCryptoBackend.getInterface();
        backend_initialized = true;
    }
}

/// Set a custom backend
pub fn setBackend(interface: CryptoInterface) void {
    current_backend = interface;
    backend_initialized = true;
}

/// Get current backend
pub fn getBackend() CryptoInterface {
    if (!backend_initialized) {
        init();
    }
    return current_backend;
}

/// zcrypto v0.3.0 backend implementation
pub const ZCryptoBackend = struct {
    pub fn getInterface() CryptoInterface {
        return CryptoInterface{
            .generateKeypairFn = zcryptoGenerateKeypair,
            .keypairFromSeedFn = zcryptoKeypairFromSeed,
            .signFn = zcryptoSign,
            .verifyFn = zcryptoVerify,
            .signWithContextFn = zcryptoSignWithContext,
            .verifyWithContextFn = zcryptoVerifyWithContext,
        };
    }
    
    fn zcryptoGenerateKeypair(allocator: std.mem.Allocator) !Keypair {
        _ = allocator; // zcrypto doesn't need allocator for Ed25519
        
        // Use zcrypto v0.3.0 Ed25519 key generation
        const keypair = zcrypto.asym.ed25519.generate();
        
        return Keypair{
            .public_key = keypair.public_key,
            .private_key = keypair.private_key,
        };
    }
    
    fn zcryptoKeypairFromSeed(seed: [SEED_SIZE]u8) Keypair {
        // Use zcrypto v0.3.0 deterministic key generation
        const keypair = zcrypto.asym.ed25519.generateFromSeed(seed);
        
        return Keypair{
            .public_key = keypair.public_key,
            .private_key = keypair.private_key,
        };
    }
    
    fn zcryptoSign(message: []const u8, keypair: Keypair) !Signature {
        // Use zcrypto v0.3.0 Ed25519 signing
        // Create a temporary keypair structure for zcrypto
        const zcrypto_keypair = zcrypto.asym.ed25519.generateFromSeed(keypair.private_key[0..32].*);
        const sig_bytes = try zcrypto_keypair.sign(message);
        
        return Signature{
            .bytes = sig_bytes,
        };
    }
    
    fn zcryptoVerify(message: []const u8, signature: [SIGNATURE_SIZE]u8, public_key: [PUBLIC_KEY_SIZE]u8) bool {
        // Use zcrypto v0.3.0 Ed25519 verification
        return zcrypto.asym.ed25519.verify(message, signature, public_key);
    }
    
    fn zcryptoSignWithContext(message: []const u8, context: []const u8, keypair: Keypair) !Signature {
        // Use domain separation with Blake2b 
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(context);
        hasher.update(message);
        
        var domain_separated_hash: [32]u8 = undefined;
        hasher.final(&domain_separated_hash);
        
        return zcryptoSign(&domain_separated_hash, keypair);
    }
    
    fn zcryptoVerifyWithContext(message: []const u8, context: []const u8, signature: [SIGNATURE_SIZE]u8, public_key: [PUBLIC_KEY_SIZE]u8) bool {
        // Use domain separation with Blake2b 
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(context);
        hasher.update(message);
        
        var domain_separated_hash: [32]u8 = undefined;
        hasher.final(&domain_separated_hash);
        
        return zcryptoVerify(&domain_separated_hash, signature, public_key);
    }
};

/// Fallback std.crypto backend
pub const StdCryptoBackend = struct {
    pub fn getInterface() CryptoInterface {
        return CryptoInterface{
            .generateKeypairFn = stdGenerateKeypair,
            .keypairFromSeedFn = stdKeypairFromSeed,
            .signFn = stdSign,
            .verifyFn = stdVerify,
            .signWithContextFn = stdSignWithContext,
            .verifyWithContextFn = stdVerifyWithContext,
        };
    }
    
    fn stdGenerateKeypair(allocator: std.mem.Allocator) !Keypair {
        _ = allocator;
        
        // Generate random seed
        var seed: [SEED_SIZE]u8 = undefined;
        std.crypto.random.bytes(&seed);
        
        // Use std.crypto Ed25519
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        
        return Keypair{
            .public_key = kp.public_key.bytes,
            .private_key = kp.secret_key.bytes,
        };
    }
    
    fn stdKeypairFromSeed(seed: [SEED_SIZE]u8) Keypair {
        // Use std.crypto Ed25519 from seed
        const kp = std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch unreachable;
        
        return Keypair{
            .public_key = kp.public_key.bytes,
            .private_key = kp.secret_key.bytes,
        };
    }
    
    fn stdSign(message: []const u8, keypair: Keypair) !Signature {
        // Reconstruct std.crypto keypair from seed (first 32 bytes of private key)
        const seed = keypair.private_key[0..32].*;
        const kp = try std.crypto.sign.Ed25519.KeyPair.generateDeterministic(seed);
        
        const sig = try kp.sign(message, null);
        return Signature{ .bytes = sig.toBytes() };
    }
    
    fn stdVerify(message: []const u8, signature: [SIGNATURE_SIZE]u8, public_key: [PUBLIC_KEY_SIZE]u8) bool {
        const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return false;
        const sig = std.crypto.sign.Ed25519.Signature.fromBytes(signature);
        
        sig.verify(message, pub_key) catch return false;
        return true;
    }
    
    fn stdSignWithContext(message: []const u8, context: []const u8, keypair: Keypair) !Signature {
        // Domain separation using Blake2b
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(context);
        hasher.update(message);
        
        var domain_separated_hash: [32]u8 = undefined;
        hasher.final(&domain_separated_hash);
        
        return stdSign(&domain_separated_hash, keypair);
    }
    
    fn stdVerifyWithContext(message: []const u8, context: []const u8, signature: [SIGNATURE_SIZE]u8, public_key: [PUBLIC_KEY_SIZE]u8) bool {
        // Recreate domain separated hash
        var hasher = std.crypto.hash.blake2.Blake2b256.init(.{});
        hasher.update(context);
        hasher.update(message);
        
        var domain_separated_hash: [32]u8 = undefined;
        hasher.final(&domain_separated_hash);
        
        return stdVerify(&domain_separated_hash, signature, public_key);
    }
};

/// Convenience functions using current backend
pub fn generateKeypair(allocator: std.mem.Allocator) !Keypair {
    return getBackend().generateKeypairFn(allocator);
}

pub fn keypairFromSeed(seed: [SEED_SIZE]u8) Keypair {
    return getBackend().keypairFromSeedFn(seed);
}

pub fn sign(message: []const u8, keypair: Keypair) !Signature {
    return getBackend().signFn(message, keypair);
}

pub fn verify(message: []const u8, signature: [SIGNATURE_SIZE]u8, public_key: [PUBLIC_KEY_SIZE]u8) bool {
    return getBackend().verifyFn(message, signature, public_key);
}

pub fn signWithContext(message: []const u8, context: []const u8, keypair: Keypair) !Signature {
    return getBackend().signWithContextFn(message, context, keypair);
}

pub fn verifyWithContext(message: []const u8, context: []const u8, signature: [SIGNATURE_SIZE]u8, public_key: [PUBLIC_KEY_SIZE]u8) bool {
    return getBackend().verifyWithContextFn(message, context, signature, public_key);
}

test "backend system" {
    const allocator = std.testing.allocator;
    
    // Test zcrypto backend
    setBackend(ZCryptoBackend.getInterface());
    
    const keypair = try generateKeypair(allocator);
    const message = "test message";
    const signature = try sign(message, keypair);
    
    try std.testing.expect(verify(message, signature.bytes, keypair.public_key));
    
    // Test std.crypto backend
    setBackend(StdCryptoBackend.getInterface());
    
    const keypair2 = try generateKeypair(allocator);
    const signature2 = try sign(message, keypair2);
    
    try std.testing.expect(verify(message, signature2.bytes, keypair2.public_key));
}
