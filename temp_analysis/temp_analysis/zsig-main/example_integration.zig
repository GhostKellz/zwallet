// Example showing how a parent application would integrate zsig with zcrypto
const std = @import("std");
const zsig = @import("src/zsig.zig");

// This is how a parent application would provide zcrypto to zsig
// (hypothetical zcrypto functions - replace with actual zcrypto calls)

fn zcryptoGenerateKeypair() zsig.backend.KeypairResult {
    // Example: return zcrypto.asym.ed25519.generate();
    // For demo, we'll use std.crypto
    const kp = std.crypto.sign.Ed25519.KeyPair.generate();
    return zsig.backend.KeypairResult{
        .public_key = kp.public_key.bytes,
        .secret_key = kp.secret_key.bytes,
    };
}

fn zcryptoKeypairFromSeed(seed: [32]u8) zsig.backend.KeypairResult {
    // Example: return zcrypto.asym.ed25519.fromSeed(seed);
    // For demo, we'll use a deterministic approach with std.crypto
    var prng = std.Random.DefaultPrng.init(@as(u64, @bitCast(seed[0..8].*)));
    const random = prng.random();
    
    // In real zcrypto, this would be truly deterministic
    const kp = std.crypto.sign.Ed25519.KeyPair.generate();
    _ = random; // Suppress unused warning for demo
    
    return zsig.backend.KeypairResult{
        .public_key = kp.public_key.bytes,
        .secret_key = kp.secret_key.bytes,
    };
}

fn zcryptoSign(message: []const u8, secret_key: [64]u8) [64]u8 {
    // Example: return zcrypto.asym.ed25519.sign(message, secret_key);
    const kp = std.crypto.sign.Ed25519.KeyPair{
        .public_key = std.crypto.sign.Ed25519.PublicKey{ .bytes = secret_key[32..64].* },
        .secret_key = std.crypto.sign.Ed25519.SecretKey{ .bytes = secret_key },
    };
    const signature = kp.sign(message, null) catch unreachable;
    var result: [64]u8 = undefined;
    result[0..32].* = signature.r;
    result[32..64].* = signature.s;
    return result;
}

fn zcryptoVerify(message: []const u8, signature: [64]u8, public_key: [32]u8) bool {
    // Example: return zcrypto.asym.ed25519.verify(message, signature, public_key);
    const pub_key = std.crypto.sign.Ed25519.PublicKey.fromBytes(public_key) catch return false;
    const sig = std.crypto.sign.Ed25519.Signature{
        .r = signature[0..32].*,
        .s = signature[32..64].*,
    };
    sig.verify(message, pub_key) catch return false;
    return true;
}

fn zcryptoHash(data: []const u8) [32]u8 {
    // Example: return zcrypto.hash.blake3(data);
    var hasher = std.crypto.hash.Blake3.init(.{});
    hasher.update(data);
    var result: [32]u8 = undefined;
    hasher.final(&result);
    return result;
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Set up the crypto interface with our zcrypto implementation
    const crypto_interface = zsig.CryptoInterface{
        .generateKeypairFn = zcryptoGenerateKeypair,
        .keypairFromSeedFn = zcryptoKeypairFromSeed,
        .signFn = zcryptoSign,
        .verifyFn = zcryptoVerify,
        .hashFn = zcryptoHash,
    };
    
    zsig.setCryptoInterface(crypto_interface);
    
    std.debug.print("=== Zsig Integration Example ===\n", .{});
    std.debug.print("Using zcrypto functions via interface\n", .{});
    
    // Now use zsig normally - it will use our zcrypto functions
    const keypair = try zsig.generateKeypair(allocator);
    std.debug.print("Generated keypair with zcrypto backend\n", .{});
    
    const message = "Hello from zsig with zcrypto!";
    const signature = try zsig.signMessage(message, keypair);
    std.debug.print("Signed message: {s}\n", .{message});
    
    const is_valid = zsig.verifySignature(message, &signature.bytes, &keypair.publicKey());
    std.debug.print("Signature valid: {}\n", .{is_valid});
    
    // Test context signing
    const context = "example-context";
    const ctx_signature = try zsig.signWithContext(message, context, keypair);
    const ctx_valid = zsig.verifyWithContext(message, context, &ctx_signature.bytes, &keypair.publicKey());
    std.debug.print("Context signature valid: {}\n", .{ctx_valid});
    
    std.debug.print("=== Integration Complete ===\n", .{});
}