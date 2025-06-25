//! Core wallet functionality
//! Manages keys, accounts, and transactions

const std = @import("std");
const zcrypto = @import("zcrypto");
const Allocator = std.mem.Allocator;
const crypto = @import("../utils/crypto.zig");
const keystore = @import("../utils/keystore.zig");

pub const WalletError = error{
    InvalidMnemonic,
    InvalidKey,
    InvalidAddress,
    InsufficientFunds,
    NetworkError,
    KeyDerivationFailed,
    UnknownProtocol,
    WalletLocked,
    InvalidPassword,
};

pub const WalletMode = enum {
    public_identity,
    private_cold,
    hybrid,
};

pub const Protocol = enum {
    ghostchain,
    ethereum,
    stellar,
    hedera,
    ripple,
};

pub const KeyType = crypto.KeyType;

pub const Account = struct {
    address: []const u8,
    protocol: Protocol,
    key_type: KeyType,
    keypair: ?crypto.KeyPair,
    name: ?[]const u8,
    balance: i64, // in micro-units
    currency: []const u8,
    
    pub fn init(allocator: Allocator, protocol: Protocol, key_type: KeyType, name: ?[]const u8) !Account {
        // Generate keypair
        var keypair = try crypto.KeyPair.generate(key_type);
        
        // Generate address from public key (simplified)
        const address = try generateAddress(allocator, &keypair.public_key, protocol);
        
        return Account{
            .address = address,
            .protocol = protocol,
            .key_type = key_type,
            .keypair = keypair,
            .name = if (name) |n| try allocator.dupe(u8, n) else null,
            .balance = 0,
            .currency = try allocator.dupe(u8, getDefaultCurrency(protocol)),
        };
    }
    
    pub fn deinit(self: *Account, allocator: Allocator) void {
        allocator.free(self.address);
        if (self.keypair) |*kp| {
            kp.deinit();
        }
        if (self.name) |n| allocator.free(n);
        allocator.free(self.currency);
    }
    
    pub fn getPublicKey(self: *const Account) ?[32]u8 {
        if (self.keypair) |kp| {
            return kp.public_key;
        }
        return null;
    }
    
    pub fn sign(self: *const Account, message: []const u8, allocator: Allocator) ![]u8 {
        if (self.keypair) |kp| {
            return try kp.sign(message, allocator);
        }
        return WalletError.InvalidKey;
    }
};

pub const Wallet = struct {
    allocator: Allocator,
    mode: WalletMode,
    accounts: std.ArrayList(Account),
    keystore_path: ?[]const u8,
    is_locked: bool,
    master_hd_node: ?crypto.HDNode,
    account_counter: u32,
    
    pub fn init(allocator: Allocator, mode: WalletMode, keystore_path: ?[]const u8) Wallet {
        return Wallet{
            .allocator = allocator,
            .mode = mode,
            .accounts = std.ArrayList(Account).init(allocator),
            .keystore_path = keystore_path,
            .is_locked = true,
            .master_hd_node = null,
            .account_counter = 0,
        };
    }
    
    pub fn deinit(self: *Wallet) void {
        for (self.accounts.items) |*account| {
            account.deinit(self.allocator);
        }
        self.accounts.deinit();
        
        // Zero out master HD node
        if (self.master_hd_node) |*node| {
            node.key.deinit();
            @memset(&node.chain_code, 0);
        }
    }
    
    /// Generate new wallet from mnemonic
    pub fn fromMnemonic(allocator: Allocator, mnemonic: []const u8, password: ?[]const u8, mode: WalletMode) !Wallet {
        // Convert mnemonic to seed using BIP-39
        const seed = try crypto.mnemonicToSeed(mnemonic, password, allocator);
        
        var wallet = Wallet.init(allocator, mode, null);
        
        // Create master HD node using BIP-32
        wallet.master_hd_node = try crypto.createHDWallet(seed, .secp256k1);
        wallet.is_locked = false;
        
        return wallet;
    }
    
    /// Generate new random wallet
    pub fn generate(allocator: Allocator, mode: WalletMode) !Wallet {
        var wallet = Wallet.init(allocator, mode, null);
        
        // Generate new mnemonic (256-bit entropy)
        const mnemonic = try crypto.generateMnemonic(allocator, 256);
        defer allocator.free(mnemonic);
        
        // Convert to seed
        const seed = try crypto.mnemonicToSeed(mnemonic, null, allocator);
        
        // Create master HD node
        wallet.master_hd_node = try crypto.createHDWallet(seed, .secp256k1);
        wallet.is_locked = false;
        
        return wallet;
    }
    
    /// Create new account for specified protocol using HD derivation
    pub fn createAccount(self: *Wallet, protocol: Protocol, key_type: KeyType, name: ?[]const u8) !void {
        if (self.is_locked) return WalletError.WalletLocked;
        
        const master_node = self.master_hd_node orelse return WalletError.InvalidKey;
        
        // Derive account key using BIP-44 path
        // m/44'/coin_type'/account_index'/0/0
        const coin_type = getCoinType(protocol);
        
        // m/44'
        const purpose_node = try master_node.deriveChild(44, true);
        defer purpose_node.key.deinit();
        
        // m/44'/coin_type'
        const coin_node = try purpose_node.deriveChild(coin_type, true);
        defer coin_node.key.deinit();
        
        // m/44'/coin_type'/account'
        const account_node = try coin_node.deriveChild(self.account_counter, true);
        defer account_node.key.deinit();
        
        // m/44'/coin_type'/account'/0
        const change_node = try account_node.deriveChild(0, false);
        defer change_node.key.deinit();
        
        // m/44'/coin_type'/account'/0/0
        const address_node = try change_node.deriveChild(0, false);
        
        // Convert key to desired type if needed
        var keypair = if (address_node.key.key_type == key_type) 
            address_node.key 
        else 
            try crypto.KeyPair.fromSeed(address_node.key.private_key[0..32].*, key_type);
        
        // Generate address from public key
        const address = try generateAddress(self.allocator, &keypair.public_key, protocol);
        
        const account = Account{
            .address = address,
            .protocol = protocol,
            .key_type = key_type,
            .keypair = keypair,
            .name = if (name) |n| try self.allocator.dupe(u8, n) else null,
            .balance = 0,
            .currency = try self.allocator.dupe(u8, getDefaultCurrency(protocol)),
        };
        
        try self.accounts.append(account);
        self.account_counter += 1;
    }
    
    /// Get account by address
    pub fn getAccount(self: *Wallet, address: []const u8) ?*Account {
        for (self.accounts.items) |*account| {
            if (std.mem.eql(u8, account.address, address)) {
                return account;
            }
        }
        return null;
    }
    
    /// Get balance for account
    pub fn getBalance(self: *Wallet, address: []const u8, currency: []const u8) !i64 {
        _ = currency;
        
        if (self.getAccount(address)) |account| {
            return account.balance;
        }
        return WalletError.InvalidAddress;
    }
    
    /// Lock wallet (clear sensitive data from memory)
    pub fn lock(self: *Wallet) void {
        self.is_locked = true;
        if (self.master_hd_node) |*node| {
            node.key.deinit();
            @memset(&node.chain_code, 0);
            self.master_hd_node = null;
        }
        
        // Clear private keys from accounts
        for (self.accounts.items) |*account| {
            if (account.keypair) |*kp| {
                kp.deinit();
                account.keypair = null;
            }
        }
    }
    
    /// Unlock wallet with password
    pub fn unlock(self: *Wallet, password: []const u8) !void {
        if (self.keystore_path) |path| {
            // Load keystore and decrypt master key
            var ks = try keystore.Keystore.loadFromFile(self.allocator, path);
            defer ks.deinit();
            
            const master_keypair = try ks.decryptKeypair(password);
            
            // Reconstruct HD node from master key
            var seed: [64]u8 = undefined;
            @memcpy(seed[0..32], &master_keypair.private_key[0..32]);
            @memcpy(seed[32..64], &master_keypair.private_key[32..64]);
            
            self.master_hd_node = try crypto.createHDWallet(seed, master_keypair.key_type);
            self.is_locked = false;
        } else {
            return WalletError.InvalidPassword;
        }
    }
    
    /// Save wallet to encrypted keystore
    pub fn save(self: *Wallet, path: []const u8, password: []const u8) !void {
        if (self.master_hd_node) |master_node| {
            var ks = keystore.Keystore.init(self.allocator);
            defer ks.deinit();
            
            try ks.encryptKeypair(&master_node.key, password, null);
            try ks.saveToFile(path);
            
            // Update keystore path
            if (self.keystore_path) |old_path| {
                self.allocator.free(old_path);
            }
            self.keystore_path = try self.allocator.dupe(u8, path);
        } else {
            return WalletError.InvalidKey;
        }
    }
    
    /// Load wallet from encrypted keystore
    pub fn load(allocator: Allocator, path: []const u8, password: []const u8) !Wallet {
        var ks = try keystore.Keystore.loadFromFile(allocator, path);
        defer ks.deinit();
        
        const master_keypair = try ks.decryptKeypair(password);
        
        var wallet = Wallet.init(allocator, .hybrid, try allocator.dupe(u8, path));
        
        // Reconstruct HD node from master key
        var seed: [64]u8 = undefined;
        @memcpy(seed[0..32], &master_keypair.private_key[0..32]);
        @memcpy(seed[32..64], &master_keypair.private_key[32..64]);
        
        wallet.master_hd_node = try crypto.createHDWallet(seed, master_keypair.key_type);
        wallet.is_locked = false;
        
        return wallet;
    }
};

/// Generate address from public key for a specific protocol
fn generateAddress(allocator: Allocator, public_key: *const [32]u8, protocol: Protocol) ![]const u8 {
    switch (protocol) {
        .ghostchain => {
            // GhostChain address format: gc_ + base58(hash(public_key))
            var hash: [32]u8 = undefined;
            std.crypto.hash.sha2.Sha256.hash(public_key, &hash, .{});
            const hex = try std.fmt.allocPrint(allocator, "gc_{}", .{std.fmt.fmtSliceHexLower(hash[0..20])});
            return hex;
        },
        .ethereum => {
            // Ethereum address: 0x + last 20 bytes of keccak256(public_key)
            var hash: [32]u8 = undefined;
            zcrypto.hash.keccak256.hash(public_key, &hash, .{});
            const hex = try std.fmt.allocPrint(allocator, "0x{}", .{std.fmt.fmtSliceHexLower(hash[12..32])});
            return hex;
        },
        .stellar => {
            // Stellar address: G + base32(public_key + checksum)
            const hex = try std.fmt.allocPrint(allocator, "G{}", .{std.fmt.fmtSliceHexUpper(public_key[0..28])});
            return hex;
        },
        .hedera => {
            // Hedera account ID format: 0.0.xxxxx
            const account_num = @as(u64, @intCast(public_key[0])) | 
                               (@as(u64, @intCast(public_key[1])) << 8) |
                               (@as(u64, @intCast(public_key[2])) << 16);
            const address = try std.fmt.allocPrint(allocator, "0.0.{}", .{account_num});
            return address;
        },
        .ripple => {
            // XRPL address: r + base58(public_key + checksum)
            const hex = try std.fmt.allocPrint(allocator, "r{}", .{std.fmt.fmtSliceHexUpper(public_key[0..25])});
            return hex;
        },
    }
}

/// Get default currency for protocol
fn getDefaultCurrency(protocol: Protocol) []const u8 {
    return switch (protocol) {
        .ghostchain => "GCC",
        .ethereum => "ETH",
        .stellar => "XLM",
        .hedera => "HBAR",
        .ripple => "XRP",
    };
}

/// Get BIP-44 coin type for protocol
fn getCoinType(protocol: Protocol) u32 {
    return switch (protocol) {
        .ghostchain => 9999, // Custom coin type
        .ethereum => 60,     // ETH
        .stellar => 148,     // XLM
        .hedera => 3030,     // HBAR
        .ripple => 144,      // XRP
    };
}

test "wallet creation" {
    var wallet = Wallet.generate(std.testing.allocator, .hybrid) catch unreachable;
    defer wallet.deinit();
    
    try std.testing.expect(!wallet.is_locked);
    try std.testing.expect(wallet.accounts.items.len == 0);
}

test "account management" {
    var wallet = Wallet.generate(std.testing.allocator, .hybrid) catch unreachable;
    defer wallet.deinit();
    
    try wallet.createAccount(.ghostchain, .ed25519, "test-account");
    try std.testing.expect(wallet.accounts.items.len == 1);
}
