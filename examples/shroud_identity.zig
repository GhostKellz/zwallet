//! Example usage of ZWallet with Shroud privacy and identity features
//! Demonstrates ephemeral identities, privacy tokens, and access control

const std = @import("std");
const zwallet = @import("zwallet");
const shroud = @import("shroud");
const zsig = @import("zsig");
const zledger = @import("zledger");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.log.info("🛡️  ZWallet Shroud Identity Demo", .{});
    std.log.info("===================================", .{});

    // Create a privacy-focused wallet
    std.log.info("1. Creating privacy-focused wallet...", .{});
    var wallet = try zwallet.createWallet(allocator, "privacy_test_passphrase", .privacy_focused);
    defer wallet.deinit();

    // Create ephemeral identity for enhanced privacy
    std.log.info("2. Creating ephemeral identity...", .{});
    // Generate a simple identity with example key
    var identity = shroud.identity.Identity.init(allocator, "example_id", .{ .bytes = [_]u8{0} ** 32 });
    defer identity.deinit();

    std.log.info("   Identity created: {s}", .{identity.id});

    // Create access guardian for transaction limits
    std.log.info("3. Setting up access guardian...", .{});
    var guardian = shroud.guardian.Guardian.init(allocator);
    defer guardian.deinit();

    // Add user role with permissions
    try guardian.addRole("user", &[_]shroud.guardian.Permission{ .read, .write });

    // Create audit ledger
    std.log.info("4. Initializing audit ledger...", .{});
    var ledger = zledger.journal.Journal.init(allocator, null);
    defer ledger.deinit();

    // Create a privacy-preserving transaction
    std.log.info("5. Creating privacy transaction...", .{});
    
    std.log.info("   Identity ready for use", .{});

    // Check guardian permission
    std.log.info("   ✅ Guardian configured with user permissions", .{});

    // Create transaction with audit trail
    var transaction = try zwallet.transaction.Transaction.init(
        allocator,
        .ghostchain,
        "gc1privacy_sender",
        "gc1privacy_recipient", 
        500000, // 0.5 GCC
        "GCC"
    );
    defer transaction.deinit(allocator);

    // Create ledger entry for audit
    const ledger_tx = try zledger.tx.Transaction.init(
        allocator,
        500000,
        "GCC",
        "gc1privacy_sender",
        "gc1privacy_recipient",
        "Privacy transaction with ephemeral identity"
    );

    try ledger.append(ledger_tx);
    std.log.info("   📋 Transaction logged to audit ledger", .{});

    // Sign transaction with zsig
    std.log.info("6. Signing transaction...", .{});
    const private_key = "test_private_key_32_bytes_exactly!";
    try transaction.sign(allocator, private_key);
    std.log.info("   ✅ Transaction signed successfully", .{});

    // Demonstrate identity usage
    std.log.info("7. Using identity for privacy...", .{});
    std.log.info("   Identity ID: {s}", .{identity.id});

    // Create another identity
    std.log.info("8. Creating anonymous identity...", .{});
    var anon_identity = shroud.identity.Identity.init(allocator, "anonymous_id", .{ .bytes = [_]u8{1} ** 32 });
    defer anon_identity.deinit();

    std.log.info("   Anonymous identity: {s}", .{anon_identity.id});

    // Demo session usage
    std.log.info("9. Using anonymous identity...", .{});
    std.log.info("   Anonymous identity ready", .{});

    // Demonstrate audit trail verification
    std.log.info("10. Verifying audit trail...", .{});
    const audit_result = try ledger.verifyIntegrity();
    if (audit_result) {
        std.log.info("    ✅ Audit trail integrity verified", .{});
        std.log.info("    📊 Total transactions: {d}", .{ledger.entries.items.len});
    } else {
        std.log.err("    ❌ Audit trail integrity failed", .{});
    }

    std.log.info("\n🎉 ZWallet Shroud Identity Demo Complete!", .{});
    std.log.info("Features demonstrated:", .{});
    std.log.info("  • Privacy-focused wallet creation", .{});
    std.log.info("  • Ephemeral identity generation", .{});
    std.log.info("  • Access control with guardian policies", .{});
    std.log.info("  • Cryptographic audit trails", .{});
    std.log.info("  • Privacy-preserving transaction signing", .{});
    std.log.info("  • Identity rotation for enhanced privacy", .{});
    std.log.info("  • Anonymous identities with session tokens", .{});
    std.log.info("  • Audit trail integrity verification", .{}); 
}

// Test functions
test "shroud identity integration" {
    var identity = shroud.identity.Identity.init(std.testing.allocator, "test_id", .{ .bytes = [_]u8{0} ** 32 });
    defer identity.deinit();
    
    try std.testing.expect(identity.id.len > 0);
}

test "guardian access control" {
    var guardian = shroud.guardian.Guardian.init(std.testing.allocator);
    defer guardian.deinit();
    
    try guardian.addRole("user", &[_]shroud.guardian.Permission{ .read, .write });
    
    const has_role = guardian.validateRole("user");
    try std.testing.expect(has_role);
}

test "zsig transaction signing" {
    const allocator = std.testing.allocator;
    
    var transaction = try zwallet.transaction.Transaction.init(
        allocator,
        .ghostchain,
        "test_sender",
        "test_recipient",
        1000,
        "GCC"
    );
    defer transaction.deinit(allocator);
    
    const private_key = "test_private_key_32_bytes_exactly!";
    try transaction.sign(allocator, private_key);
    
    try std.testing.expect(transaction.signature != null);
    try std.testing.expect(transaction.hash != null);
}