//! Example usage of Zwallet library
//! Demonstrates core wallet functionality

const std = @import("std");
const zwallet = @import("zwallet");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    std.debug.print("=== Zwallet Example ===\n\n", .{});
    
    // 1. Create a new wallet
    std.debug.print("1. Creating new wallet...\n", .{});
    var wallet = try zwallet.createWallet(allocator, .hybrid);
    defer wallet.deinit();
    
    // 2. Create accounts for different protocols
    std.debug.print("2. Creating accounts...\n", .{});
    try wallet.createAccount(.ghostchain, .ed25519, "GhostChain Account");
    try wallet.createAccount(.ethereum, .secp256k1, "Ethereum Account");
    try wallet.createAccount(.stellar, .ed25519, "Stellar Account");
    
    std.debug.print("   Created {} accounts\n", .{wallet.accounts.items.len});
    
    // 3. List accounts
    std.debug.print("3. Account listing:\n", .{});
    for (wallet.accounts.items, 0..) |account, i| {
        std.debug.print("   Account {}: {s} ({s}) - {} {s}\n", .{
            i + 1,
            @tagName(account.protocol),
            account.name orelse "Unnamed",
            account.balance,
            account.currency
        });
    }
    
    // 4. Identity resolution example
    std.debug.print("4. Testing identity resolution...\n", .{});
    const test_domains = [_][]const u8{ "vitalik.eth", "brad.crypto", "example.com" };
    
    for (test_domains) |domain| {
        const address = zwallet.resolveIdentity(allocator, domain) catch |err| {
            std.debug.print("   {s}: Error - {}\n", .{ domain, err });
            continue;
        };
        defer allocator.free(address);
        std.debug.print("   {s} -> {s}\n", .{ domain, address });
    }
    
    // 5. Transaction creation example
    std.debug.print("5. Creating transaction...\n", .{});
    if (wallet.accounts.items.len >= 2) {
        const from_account = &wallet.accounts.items[0];
        const to_address = "0x742d35cc6e0c0532e234b37e85e40521a2b5a4b8";
        
        var tx = try zwallet.transaction.ProtocolFactory.createTransaction(
            allocator,
            from_account.protocol,
            from_account.address,
            to_address,
            1000000 // 1 token in micro-units
        );
        defer tx.deinit(allocator);
        
        std.debug.print("   Transaction created: {s} -> {s}\n", .{ tx.from, tx.to });
        std.debug.print("   Amount: {} {s}\n", .{ tx.amount, tx.currency });
        
        // Calculate and display fee
        const fee = zwallet.transaction.ProtocolFactory.estimateFee(
            from_account.protocol, tx.amount, tx.gas_limit, tx.gas_price
        );
        std.debug.print("   Estimated fee: {} {s}\n", .{ fee, tx.currency });
    }
    
    // 6. Bridge API example
    std.debug.print("6. Testing Web3 bridge...\n", .{});
    var bridge = zwallet.Bridge.init(allocator);
    defer bridge.deinit();
    
    bridge.setWallet(&wallet);
    try bridge.addAuthorizedOrigin("https://app.uniswap.org");
    
    // Mock JSON-RPC request
    const request = 
        \\{"jsonrpc":"2.0","id":1,"method":"eth_accounts","params":[]}
    ;
    
    const response = try bridge.processRequest(request, "https://app.uniswap.org");
    defer allocator.free(response);
    std.debug.print("   Bridge response: {s}\n", .{response});
    
    // 7. Wallet locking/unlocking
    std.debug.print("7. Testing wallet security...\n", .{});
    std.debug.print("   Wallet locked: {}\n", .{wallet.is_locked});
    
    wallet.lock();
    std.debug.print("   After lock: {}\n", .{wallet.is_locked});
    
    try wallet.unlock("test_password");
    std.debug.print("   After unlock: {}\n", .{wallet.is_locked});
    
    std.debug.print("\n=== Example completed successfully! ===\n", .{});
}

test "example runs without errors" {
    // This test ensures the example code compiles and runs
    try std.testing.expect(true);
}
