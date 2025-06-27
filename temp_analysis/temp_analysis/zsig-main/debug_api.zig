const std = @import("std");

pub fn main() void {
    // Check Ed25519 API
    const Ed25519 = std.crypto.sign.Ed25519;
    std.debug.print("Ed25519 methods available\n", .{});
    
    // Let's see what methods are available
    _ = Ed25519;
}
