# ZWallet Implementation Guide

This guide will help you implement ZWallet, a secure cryptocurrency wallet using the zsig cryptographic signing library.

## Project Overview

ZWallet is designed to be a lightweight, secure cryptocurrency wallet that leverages:
- **zsig** - Ed25519 cryptographic signing for transaction security
- **zcrypto** - Low-level cryptographic primitives
- **realid** - Identity management and authentication
- **tokioz** - Async runtime for network operations

## Architecture

```
ZWallet/
├── src/
│   ├── root.zig              # Main library entry point
│   ├── wallet/
│   │   ├── core.zig          # Core wallet functionality
│   │   ├── transaction.zig   # Transaction handling
│   │   ├── keystore.zig      # Key management and storage
│   │   └── crypto.zig        # Cryptographic operations
│   ├── network/
│   │   ├── client.zig        # Network client
│   │   ├── protocol.zig      # Protocol definitions
│   │   └── sync.zig          # Blockchain synchronization
│   ├── storage/
│   │   ├── database.zig      # Local storage
│   │   ├── backup.zig        # Backup/restore functionality
│   │   └── migration.zig     # Database migrations
│   ├── ui/
│   │   ├── cli.zig           # Command-line interface
│   │   ├── commands.zig      # CLI command implementations
│   │   └── display.zig       # Output formatting
│   └── main.zig              # Application entry point
├── build.zig                 # Build configuration
├── build.zig.zon             # Dependencies
└── README.md
```

## Dependencies Setup

Your `build.zig.zon` should include:

```zig
.dependencies = .{
    .zcrypto = .{
        .url = "https://github.com/ghostkellz/zcrypto/archive/refs/heads/main.tar.gz",
        .hash = "1220e39c012a9a344dd939a145af8ef2549c3486b4c699194b9f6df06ad62267bf49",
    },
    .realid = .{
        .url = "https://github.com/ghostkellz/realid/archive/refs/tags/v0.2.0.tar.gz",
        .hash = "YOUR_REALID_HASH_HERE",
    },
    .zsig = .{
        .path = "../zsig",  // Local path to zsig
    },
    .tokioz = .{
        .url = "https://github.com/ghostkellz/tokioz/archive/refs/heads/main.tar.gz",
        .hash = "YOUR_TOKIOZ_HASH_HERE",
        .lazy = true,
    },
},
```

## Core Implementation Steps

### 1. Wallet Core Module (`src/wallet/core.zig`)

```zig
const std = @import("std");
const zsig = @import("zsig");
const zcrypto = @import("zcrypto");
const realid = @import("realid");

pub const Wallet = struct {
    keypair: zsig.Keypair,
    identity: realid.Identity,
    balance: u64,
    transactions: std.ArrayList(Transaction),
    allocator: std.mem.Allocator,
    
    pub fn init(allocator: std.mem.Allocator) !Wallet {
        const keypair = try zsig.generateKeypair(allocator);
        const identity = try realid.Identity.create(allocator);
        
        return Wallet{
            .keypair = keypair,
            .identity = identity,
            .balance = 0,
            .transactions = std.ArrayList(Transaction).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn fromSeed(allocator: std.mem.Allocator, seed: [32]u8) !Wallet {
        const keypair = zsig.keypairFromSeed(seed);
        const identity = try realid.Identity.fromSeed(allocator, seed);
        
        return Wallet{
            .keypair = keypair,
            .identity = identity,
            .balance = 0,
            .transactions = std.ArrayList(Transaction).init(allocator),
            .allocator = allocator,
        };
    }
    
    pub fn getAddress(self: Wallet) []const u8 {
        return &self.keypair.publicKey();
    }
    
    pub fn signTransaction(self: Wallet, transaction: *Transaction) !void {
        const tx_bytes = try transaction.serialize(self.allocator);
        defer self.allocator.free(tx_bytes);
        
        const signature = try zsig.signMessage(tx_bytes, self.keypair);
        transaction.signature = signature.bytes;
    }
};
```

### 2. Transaction Module (`src/wallet/transaction.zig`)

```zig
const std = @import("std");
const zsig = @import("zsig");

pub const Transaction = struct {
    from: [32]u8,
    to: [32]u8,
    amount: u64,
    fee: u64,
    nonce: u64,
    timestamp: i64,
    signature: [64]u8,
    hash: [32]u8,
    
    pub fn create(from: [32]u8, to: [32]u8, amount: u64, fee: u64, nonce: u64) Transaction {
        const timestamp = std.time.timestamp();
        var tx = Transaction{
            .from = from,
            .to = to,
            .amount = amount,
            .fee = fee,
            .nonce = nonce,
            .timestamp = timestamp,
            .signature = std.mem.zeroes([64]u8),
            .hash = std.mem.zeroes([32]u8),
        };
        
        tx.updateHash();
        return tx;
    }
    
    pub fn serialize(self: Transaction, allocator: std.mem.Allocator) ![]u8 {
        var list = std.ArrayList(u8).init(allocator);
        defer list.deinit();
        
        try list.appendSlice(&self.from);
        try list.appendSlice(&self.to);
        try list.appendSlice(std.mem.asBytes(&self.amount));
        try list.appendSlice(std.mem.asBytes(&self.fee));
        try list.appendSlice(std.mem.asBytes(&self.nonce));
        try list.appendSlice(std.mem.asBytes(&self.timestamp));
        
        return list.toOwnedSlice();
    }
    
    pub fn verify(self: Transaction, public_key: [32]u8) bool {
        const tx_bytes = self.serialize(std.heap.page_allocator) catch return false;
        defer std.heap.page_allocator.free(tx_bytes);
        
        return zsig.verifySignature(tx_bytes, &self.signature, &public_key);
    }
    
    fn updateHash(self: *Transaction) void {
        // Implement hash calculation using zcrypto
        const tx_bytes = self.serialize(std.heap.page_allocator) catch return;
        defer std.heap.page_allocator.free(tx_bytes);
        
        // Use zcrypto to compute SHA256 hash
        self.hash = zcrypto.hash.sha256(tx_bytes);
    }
};
```

### 3. Keystore Module (`src/wallet/keystore.zig`)

```zig
const std = @import("std");
const zsig = @import("zsig");
const zcrypto = @import("zcrypto");

pub const Keystore = struct {
    encrypted_data: []u8,
    salt: [32]u8,
    allocator: std.mem.Allocator,
    
    pub fn create(allocator: std.mem.Allocator, keypair: zsig.Keypair, password: []const u8) !Keystore {
        const salt = zcrypto.random.bytes(32);
        const key = try zcrypto.kdf.pbkdf2(allocator, password, &salt, 100000, 32);
        defer allocator.free(key);
        
        const secret_key = keypair.secretKey();
        const encrypted = try zcrypto.aead.encrypt(allocator, &secret_key, key, &salt);
        
        return Keystore{
            .encrypted_data = encrypted,
            .salt = salt,
            .allocator = allocator,
        };
    }
    
    pub fn unlock(self: Keystore, password: []const u8) !zsig.Keypair {
        const key = try zcrypto.kdf.pbkdf2(self.allocator, password, &self.salt, 100000, 32);
        defer self.allocator.free(key);
        
        const decrypted = try zcrypto.aead.decrypt(self.allocator, self.encrypted_data, key, &self.salt);
        defer self.allocator.free(decrypted);
        
        if (decrypted.len != 32) return error.InvalidKeystore;
        
        const seed = decrypted[0..32].*;
        return zsig.keypairFromSeed(seed);
    }
    
    pub fn save(self: Keystore, path: []const u8) !void {
        const file = try std.fs.cwd().createFile(path, .{});
        defer file.close();
        
        try file.writeAll(&self.salt);
        try file.writeAll(self.encrypted_data);
    }
    
    pub fn load(allocator: std.mem.Allocator, path: []const u8) !Keystore {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        
        const file_size = try file.getEndPos();
        if (file_size < 32) return error.InvalidKeystore;
        
        var salt: [32]u8 = undefined;
        _ = try file.readAll(&salt);
        
        const encrypted_size = file_size - 32;
        const encrypted_data = try allocator.alloc(u8, encrypted_size);
        _ = try file.readAll(encrypted_data);
        
        return Keystore{
            .encrypted_data = encrypted_data,
            .salt = salt,
            .allocator = allocator,
        };
    }
};
```

### 4. CLI Interface (`src/ui/cli.zig`)

```zig
const std = @import("std");
const Wallet = @import("../wallet/core.zig").Wallet;
const Transaction = @import("../wallet/transaction.zig").Transaction;
const Keystore = @import("../wallet/keystore.zig").Keystore;

pub const CLI = struct {
    allocator: std.mem.Allocator,
    wallet: ?Wallet,
    
    pub fn init(allocator: std.mem.Allocator) CLI {
        return CLI{
            .allocator = allocator,
            .wallet = null,
        };
    }
    
    pub fn run(self: *CLI) !void {
        const args = try std.process.argsAlloc(self.allocator);
        defer std.process.argsFree(self.allocator, args);
        
        if (args.len < 2) {
            try self.printHelp();
            return;
        }
        
        const command = args[1];
        
        if (std.mem.eql(u8, command, "create")) {
            try self.createWallet();
        } else if (std.mem.eql(u8, command, "unlock")) {
            try self.unlockWallet();
        } else if (std.mem.eql(u8, command, "balance")) {
            try self.showBalance();
        } else if (std.mem.eql(u8, command, "send")) {
            if (args.len < 4) {
                std.debug.print("Usage: zwallet send <address> <amount>\n", .{});
                return;
            }
            try self.sendTransaction(args[2], args[3]);
        } else if (std.mem.eql(u8, command, "address")) {
            try self.showAddress();
        } else {
            try self.printHelp();
        }
    }
    
    fn createWallet(self: *CLI) !void {
        std.debug.print("Creating new wallet...\n", .{});
        
        const wallet = try Wallet.init(self.allocator);
        self.wallet = wallet;
        
        std.debug.print("Enter password to encrypt wallet: ");
        var password_buf: [256]u8 = undefined;
        const password = try self.readPassword(&password_buf);
        
        const keystore = try Keystore.create(self.allocator, wallet.keypair, password);
        try keystore.save("wallet.dat");
        
        std.debug.print("Wallet created successfully!\n", .{});
        std.debug.print("Address: {s}\n", .{std.fmt.fmtSliceHexLower(&wallet.getAddress())});
    }
    
    fn unlockWallet(self: *CLI) !void {
        std.debug.print("Enter wallet password: ");
        var password_buf: [256]u8 = undefined;
        const password = try self.readPassword(&password_buf);
        
        const keystore = try Keystore.load(self.allocator, "wallet.dat");
        const keypair = try keystore.unlock(password);
        
        self.wallet = try Wallet.fromKeypair(self.allocator, keypair);
        std.debug.print("Wallet unlocked successfully!\n", .{});
    }
    
    fn showBalance(self: *CLI) !void {
        if (self.wallet == null) {
            std.debug.print("Wallet not unlocked. Run 'zwallet unlock' first.\n", .{});
            return;
        }
        
        std.debug.print("Balance: {} tokens\n", .{self.wallet.?.balance});
    }
    
    fn showAddress(self: *CLI) !void {
        if (self.wallet == null) {
            std.debug.print("Wallet not unlocked. Run 'zwallet unlock' first.\n", .{});
            return;
        }
        
        std.debug.print("Address: {s}\n", .{std.fmt.fmtSliceHexLower(&self.wallet.?.getAddress())});
    }
    
    fn sendTransaction(self: *CLI, to_address: []const u8, amount_str: []const u8) !void {
        if (self.wallet == null) {
            std.debug.print("Wallet not unlocked. Run 'zwallet unlock' first.\n", .{});
            return;
        }
        
        const amount = try std.fmt.parseInt(u64, amount_str, 10);
        
        // Parse destination address
        var to_bytes: [32]u8 = undefined;
        _ = try std.fmt.hexToBytes(&to_bytes, to_address);
        
        // Create and sign transaction
        var transaction = Transaction.create(
            self.wallet.?.getAddress(),
            to_bytes,
            amount,
            1000, // fee
            self.wallet.?.transactions.items.len
        );
        
        try self.wallet.?.signTransaction(&transaction);
        
        std.debug.print("Transaction created: {s}\n", .{std.fmt.fmtSliceHexLower(&transaction.hash)});
        std.debug.print("Send this transaction to the network to complete.\n", .{});
    }
    
    fn readPassword(self: *CLI, buffer: []u8) ![]const u8 {
        _ = self;
        const stdin = std.io.getStdIn().reader();
        if (try stdin.readUntilDelimiterOrEof(buffer, '\n')) |input| {
            return std.mem.trim(u8, input, " \n\r\t");
        }
        return error.NoInput;
    }
    
    fn printHelp(self: *CLI) !void {
        _ = self;
        std.debug.print("ZWallet - Secure Cryptocurrency Wallet\n\n", .{});
        std.debug.print("Commands:\n", .{});
        std.debug.print("  create                    Create a new wallet\n", .{});
        std.debug.print("  unlock                    Unlock existing wallet\n", .{});
        std.debug.print("  balance                   Show wallet balance\n", .{});
        std.debug.print("  address                   Show wallet address\n", .{});
        std.debug.print("  send <address> <amount>   Send tokens to address\n", .{});
        std.debug.print("  help                      Show this help message\n", .{});
    }
};
```

### 5. Build Configuration (`build.zig`)

```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Get dependencies
    const zcrypto_dep = b.dependency("zcrypto", .{
        .target = target,
        .optimize = optimize,
    });
    const zcrypto_mod = zcrypto_dep.module("zcrypto");

    const realid_dep = b.dependency("realid", .{
        .target = target,
        .optimize = optimize,
    });
    const realid_mod = realid_dep.module("realid");

    const zsig_dep = b.dependency("zsig", .{
        .target = target,
        .optimize = optimize,
    });
    const zsig_mod = zsig_dep.module("zsig");

    // ZWallet library module
    const zwallet_mod = b.addModule("zwallet", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .imports = &.{
            .{ .name = "zcrypto", .module = zcrypto_mod },
            .{ .name = "realid", .module = realid_mod },
            .{ .name = "zsig", .module = zsig_mod },
        },
    });

    // ZWallet CLI executable
    const exe = b.addExecutable(.{
        .name = "zwallet",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "zwallet", .module = zwallet_mod },
                .{ .name = "zcrypto", .module = zcrypto_mod },
                .{ .name = "realid", .module = realid_mod },
                .{ .name = "zsig", .module = zsig_mod },
            },
        }),
    });

    b.installArtifact(exe);

    // Run command
    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run ZWallet");
    run_step.dependOn(&run_cmd.step);

    // Tests
    const lib_tests = b.addTest(.{
        .root_module = zwallet_mod,
    });
    const run_lib_tests = b.addRunArtifact(lib_tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_lib_tests.step);
}
```

## Implementation Checklist

- [ ] Set up project structure with proper directories
- [ ] Configure `build.zig` and `build.zig.zon` with all dependencies
- [ ] Implement core wallet functionality with zsig integration
- [ ] Create transaction handling with Ed25519 signatures
- [ ] Implement encrypted keystore using zcrypto
- [ ] Build CLI interface for user interaction
- [ ] Add network client for blockchain communication
- [ ] Implement local storage and backup systems
- [ ] Add comprehensive tests for all modules
- [ ] Create documentation and examples

## Security Considerations

1. **Key Management**: Always encrypt private keys with strong passwords
2. **Signature Verification**: Verify all transactions before processing
3. **Secure Storage**: Use proper encryption for wallet files
4. **Input Validation**: Validate all user inputs and network data
5. **Error Handling**: Don't leak sensitive information in error messages

## Testing

```bash
# Build the project
zig build

# Run tests
zig build test

# Run the CLI
zig build run -- help
```

## Next Steps

1. Start with the core wallet module
2. Implement transaction signing using zsig
3. Add keystore encryption with zcrypto
4. Build the CLI interface
5. Add network functionality
6. Implement storage and backup
7. Add comprehensive tests

This architecture provides a solid foundation for a secure cryptocurrency wallet using the zsig signing library.