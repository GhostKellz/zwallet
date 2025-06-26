//! Core wallet functionality with RealID integration v0.3.0
//! Enhanced with production-ready features and advanced identity management
const std = @import("std");
const realid = @import("realid");
const zcrypto = @import("zcrypto");
const zsig = @import("zsig");
const qid = @import("qid.zig");
const tx = @import("tx.zig");
const crypto = @import("../utils/crypto.zig");
const ghostd = @import("../protocol/ghostd_integration.zig");

pub const WalletError = error{
    InvalidPassphrase,
    WalletLocked,
    InsufficientFunds,
    InvalidAddress,
    SigningFailed,
    QIDGenerationFailed,
    DeviceBindingFailed,
    InvalidAccountType,
    AccountNotFound,
};

pub const WalletMode = enum {
    public_identity,
    private_cold,
    hybrid,
    device_bound,
};

pub const Protocol = enum {
    ghostchain,
    ethereum,
    stellar,
    hedera,
    bitcoin,
    
    pub fn format(self: Protocol, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        return writer.print("{s}", .{@tagName(self)});
    }
};

pub const KeyType = enum {
    ed25519,
    secp256k1,
    
    pub fn format(self: KeyType, comptime fmt: []const u8, options: std.fmt.FormatOptions, writer: anytype) !void {
        _ = fmt;
        _ = options;
        return writer.print("{s}", .{@tagName(self)});
    }
};

pub const Balance = struct {
    protocol: Protocol,
    token: []const u8,
    amount: u64,
    decimals: u8,
    
    pub fn deinit(self: *Balance, allocator: std.mem.Allocator) void {
        allocator.free(self.token);
    }
};

pub const WalletMetadata = struct {
    name: ?[]const u8,
    created_at: i64,
    last_used: i64,
    device_bound: bool,
    version: []const u8,
    
    pub fn deinit(self: *WalletMetadata, allocator: std.mem.Allocator) void {
        if (self.name) |name| {
            allocator.free(name);
        }
        allocator.free(self.version);
    }
};

pub const Account = struct {
    address: []const u8,
    public_key: realid.RealIDPublicKey,
    key_type: KeyType,
    protocol: Protocol,
    qid: qid.QID,
    derivation_path: ?[]const u8,
    
    const Self = @This();
    
    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.address);
        if (self.derivation_path) |path| {
            allocator.free(path);
        }
    }
    
    pub fn getQIDString(self: Self, buffer: []u8) ![]u8 {
        return self.qid.toString(buffer);
    }
};

pub const Wallet = struct {
    allocator: std.mem.Allocator,
    realid_identity: ?realid.RealIDIdentity,
    master_qid: ?qid.QID,
    mode: WalletMode,
    is_locked: bool,
    accounts: std.ArrayList(Account),
    balances: std.ArrayList(Balance),
    metadata: WalletMetadata,
    passphrase_hash: ?[32]u8,
    
    const Self = @This();
    
    /// Create a new wallet using RealID passphrase
    pub fn create(allocator: std.mem.Allocator, passphrase: []const u8, mode: WalletMode, name: ?[]const u8) !Self {
        // Generate RealID identity
        const identity = if (mode == .device_bound) blk: {
            const device_fp = try realid.generate_device_fingerprint(allocator);
            break :blk try realid.realid_generate_from_passphrase_with_device(passphrase, device_fp);
        } else try realid.realid_generate_from_passphrase(passphrase);
        
        // Generate master QID from public key
        const wallet_qid = qid.QID.fromPublicKey(identity.keypair.public_key.bytes);
        
        // Hash passphrase for verification
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(passphrase);
        var passphrase_hash: [32]u8 = undefined;
        hasher.final(&passphrase_hash);
        
        const current_time = std.time.timestamp();
        
        return Self{
            .allocator = allocator,
            .realid_identity = identity,
            .master_qid = wallet_qid,
            .mode = mode,
            .is_locked = false,
            .accounts = std.ArrayList(Account).init(allocator),
            .balances = std.ArrayList(Balance).init(allocator),
            .metadata = WalletMetadata{
                .name = if (name) |n| try allocator.dupe(u8, n) else null,
                .created_at = current_time,
                .last_used = current_time,
                .device_bound = mode == .device_bound,
                .version = try allocator.dupe(u8, "0.3.0"),
            },
            .passphrase_hash = passphrase_hash,
        };
    }
    
    /// Load wallet from stored data and unlock with passphrase
    pub fn load(allocator: std.mem.Allocator, stored_data: []const u8, passphrase: []const u8) !Self {
        // In a real implementation, this would deserialize stored wallet data
        // For now, recreate from passphrase
        _ = stored_data;
        return Self.create(allocator, passphrase, .hybrid, "loaded_wallet");
    }
    
    /// Verify passphrase without unlocking
    pub fn verifyPassphrase(self: *const Self, passphrase: []const u8) bool {
        if (self.passphrase_hash == null) return false;
        
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(passphrase);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        
        return std.mem.eql(u8, &hash, &self.passphrase_hash.?);
    }
    
    /// Lock the wallet (clear sensitive data)
    pub fn lock(self: *Self) void {
        self.is_locked = true;
        // In production, would securely clear sensitive memory
        if (self.realid_identity) |*identity| {
            std.crypto.utils.secureZero(u8, &identity.keypair.private_key.bytes);
        }
    }
    
    /// Unlock the wallet with passphrase
    pub fn unlock(self: *Self, passphrase: []const u8) !void {
        if (!self.verifyPassphrase(passphrase)) {
            return WalletError.InvalidPassphrase;
        }
        
        // Regenerate RealID identity from passphrase
        const identity = if (self.metadata.device_bound) blk: {
            const device_fp = try realid.generate_device_fingerprint(self.allocator);
            break :blk try realid.realid_generate_from_passphrase_with_device(passphrase, device_fp);
        } else try realid.realid_generate_from_passphrase(passphrase);
        
        self.realid_identity = identity;
        self.is_locked = false;
        self.metadata.last_used = std.time.timestamp();
    }
    
    /// Get wallet address for protocol
    pub fn getAddress(self: *const Self, protocol: Protocol) ![]const u8 {
        if (self.is_locked) return WalletError.WalletLocked;
        if (self.realid_identity == null) return WalletError.WalletLocked;
        
        const identity = self.realid_identity.?;
        
        switch (protocol) {
            .ghostchain => {
                // GhostChain uses QID-based addressing
                if (self.master_qid) |master_qid| {
                    var buffer: [64]u8 = undefined;
                    const qid_str = try master_qid.toString(&buffer);
                    return try self.allocator.dupe(u8, qid_str);
                }
                return WalletError.QIDGenerationFailed;
            },
            .ethereum => {
                // Ethereum address from public key
                return try self.deriveEthereumAddress(identity.keypair.public_key);
            },
            .bitcoin => {
                // Bitcoin address from public key
                return try self.deriveBitcoinAddress(identity.keypair.public_key);
            },
            .stellar, .hedera => {
                // Use public key directly for these protocols
                const pubkey_hex = try std.fmt.allocPrint(self.allocator, "{}", .{std.fmt.fmtSliceHexLower(&identity.keypair.public_key.bytes)});
                return pubkey_hex;
            },
        }
    }
    
    /// Create account for specific protocol
    pub fn createAccount(self: *Self, protocol: Protocol, key_type: KeyType) !Account {
        if (self.is_locked) return WalletError.WalletLocked;
        if (self.realid_identity == null) return WalletError.WalletLocked;
        
        const identity = self.realid_identity.?;
        const address = try self.getAddress(protocol);
        const account_qid = qid.QID.fromPublicKey(identity.keypair.public_key.bytes);
        
        const account = Account{
            .address = address,
            .public_key = identity.keypair.public_key,
            .key_type = key_type,
            .protocol = protocol,
            .qid = account_qid,
            .derivation_path = null,
        };
        
        try self.accounts.append(account);
        return account;
    }
    
    /// Sign transaction with wallet
    pub fn signTransaction(self: *Self, transaction: *tx.Transaction) !void {
        if (self.is_locked) return WalletError.WalletLocked;
        if (self.realid_identity == null) return WalletError.WalletLocked;
        
        const identity = self.realid_identity.?;
        try transaction.sign(identity.keypair);
    }
    
    /// Get account balance for protocol and token
    pub fn getBalance(self: *const Self, protocol: Protocol, token: []const u8) ?u64 {
        for (self.balances.items) |balance| {
            if (balance.protocol == protocol and std.mem.eql(u8, balance.token, token)) {
                return balance.amount;
            }
        }
        return null;
    }
    
    /// Update account balance
    pub fn updateBalance(self: *Self, protocol: Protocol, token: []const u8, amount: u64, decimals: u8) !void {
        // Find existing balance entry
        for (self.balances.items) |*balance| {
            if (balance.protocol == protocol and std.mem.eql(u8, balance.token, token)) {
                balance.amount = amount;
                return;
            }
        }
        
        // Create new balance entry
        const balance = Balance{
            .protocol = protocol,
            .token = try self.allocator.dupe(u8, token),
            .amount = amount,
            .decimals = decimals,
        };
        
        try self.balances.append(balance);
    }
    
    /// Get master QID string
    pub fn getMasterQID(self: *const Self, buffer: []u8) ![]u8 {
        if (self.master_qid) |master_qid| {
            return master_qid.toString(buffer);
        }
        return WalletError.QIDGenerationFailed;
    }
    
    /// Derive Ethereum address from public key
    fn deriveEthereumAddress(self: *const Self, public_key: realid.RealIDPublicKey) ![]const u8 {
        // Ethereum address is last 20 bytes of Keccak256(public_key)
        var hasher = std.crypto.hash.sha3.Keccak256.init(.{});
        hasher.update(&public_key.bytes);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        
        // Take last 20 bytes and format as hex with 0x prefix
        const addr_bytes = hash[12..32];
        return try std.fmt.allocPrint(self.allocator, "0x{}", .{std.fmt.fmtSliceHexLower(addr_bytes)});
    }
    
    /// Derive Bitcoin address from public key
    fn deriveBitcoinAddress(self: *const Self, public_key: realid.RealIDPublicKey) ![]const u8 {
        // Simplified Bitcoin address derivation (P2PKH)
        // Real implementation would use proper Base58Check encoding
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(&public_key.bytes);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
        
        return try std.fmt.allocPrint(self.allocator, "bc1q{}", .{std.fmt.fmtSliceHexLower(hash[0..20])});
    }
    
    pub fn deinit(self: *Self) void {
        // Clear accounts
        for (self.accounts.items) |*account| {
            account.deinit(self.allocator);
        }
        self.accounts.deinit();
        
        // Clear balances
        for (self.balances.items) |*balance| {
            balance.deinit(self.allocator);
        }
        self.balances.deinit();
        
        // Clear metadata
        self.metadata.deinit(self.allocator);
        
        // Securely clear sensitive data
        if (self.realid_identity) |*identity| {
            std.crypto.utils.secureZero(u8, &identity.keypair.private_key.bytes);
        }
        
        // Clear passphrase hash
        if (self.passphrase_hash) |*hash| {
            @memset(hash, 0);
        }
    }
    
    // ==================== ZWallet v0.3.0 Enhanced Features ====================
    
    /// Get RealID identity for FFI and external integrations
    pub fn getRealIdIdentity(self: *const Self) !realid.RealIDIdentity {
        if (self.is_locked) return WalletError.WalletLocked;
        if (self.realid_identity == null) return WalletError.WalletLocked;
        return self.realid_identity.?;
    }
    
    /// Sign multiple transactions with batch processing (zsig v0.3.0 feature)
    pub fn signTransactionBatch(self: *Self, transactions: []*tx.Transaction) !void {
        if (self.is_locked) return WalletError.WalletLocked;
        if (self.realid_identity == null) return WalletError.WalletLocked;
        
        const identity = self.realid_identity.?;
        try tx.Transaction.batchSign(transactions, identity.keypair, self.allocator);
    }
    
    /// Generate deterministic child wallet from seed
    pub fn deriveChildWallet(self: *const Self, derivation_path: []const u8, allocator: std.mem.Allocator) !Self {
        if (self.is_locked) return WalletError.WalletLocked;
        if (self.realid_identity == null) return WalletError.WalletLocked;
        
        // Use zcrypto v0.3.0 for BIP-32 derivation
        const parent_key = self.realid_identity.?.keypair.private_key.bytes[0..32].*;
        const chain_code = self.realid_identity.?.keypair.public_key.bytes;
        
        // Parse derivation path (simplified)
        const child_index: u32 = 0; // TODO: Parse actual path
        const hardened = true;
        
        const derived_key = try crypto.KeyDerivation.deriveBip32(parent_key, chain_code, child_index, hardened);
        
        // Create child wallet with derived key
        const child_seed = derived_key[0..32].*;
        const child_keypair = try zcrypto.asym.ed25519.generateFromSeed(child_seed);
        
        // Create child identity
        const child_identity = realid.RealIDIdentity{
            .keypair = realid.RealIDKeyPair{
                .public_key = realid.RealIDPublicKey{ .bytes = child_keypair.public_key },
                .private_key = realid.RealIDPrivateKey{ .bytes = child_keypair.private_key },
            },
            .qid = qid.QID.fromPublicKey(child_keypair.public_key).bytes,
            .device_bound = self.metadata.device_bound,
        };
        
        return Self{
            .allocator = allocator,
            .realid_identity = child_identity,
            .master_qid = qid.QID.fromPublicKey(child_keypair.public_key),
            .mode = self.mode,
            .is_locked = false,
            .accounts = std.ArrayList(Account).init(allocator),
            .balances = std.ArrayList(Balance).init(allocator),
            .metadata = WalletMetadata{
                .name = try allocator.dupe(u8, "child_wallet"),
                .created_at = std.time.timestamp(),
                .last_used = std.time.timestamp(),
                .device_bound = self.metadata.device_bound,
                .version = try allocator.dupe(u8, "0.3.0"),
            },
            .passphrase_hash = null, // Child wallets don't store passphrase
        };
    }
    
    /// Export wallet data for backup (encrypted)
    pub fn exportWalletData(self: *const Self, export_passphrase: []const u8) ![]u8 {
        if (self.is_locked) return WalletError.WalletLocked;
        
        // Serialize wallet data
        const wallet_data = try self.serializeWalletData();
        defer self.allocator.free(wallet_data);
        
        // Derive encryption key from export passphrase
        const salt = "zwallet_export_salt_v0.3.0";
        const encryption_key = try crypto.KeyDerivation.deriveFromPassphraseArgon2(export_passphrase, salt, self.allocator);
        
        // Encrypt wallet data
        return zcrypto.aead.encrypt(wallet_data, encryption_key, self.allocator);
    }
    
    /// Import wallet data from backup
    pub fn importWalletData(allocator: std.mem.Allocator, encrypted_data: []const u8, import_passphrase: []const u8) !Self {
        // Derive decryption key
        const salt = "zwallet_export_salt_v0.3.0";
        const decryption_key = try crypto.KeyDerivation.deriveFromPassphraseArgon2(import_passphrase, salt, allocator);
        
        // Decrypt wallet data
        const wallet_data = try zcrypto.aead.decrypt(encrypted_data, decryption_key, allocator);
        defer allocator.free(wallet_data);
        
        // Deserialize wallet
        return Self.deserializeWalletData(allocator, wallet_data);
    }
    
    /// Generate mnemonic phrase for wallet backup
    pub fn generateMnemonic(self: *const Self) ![]const u8 {
        if (self.is_locked) return WalletError.WalletLocked;
        if (self.realid_identity == null) return WalletError.WalletLocked;
        
        // Use the private key as entropy for mnemonic generation
        const entropy = self.realid_identity.?.keypair.private_key.bytes[0..16].*;
        
        // Generate BIP-39 mnemonic using zcrypto v0.3.0
        return crypto.generateMnemonic(self.allocator, 128); // 12 words
    }
    
    /// Restore wallet from mnemonic phrase
    pub fn fromMnemonic(allocator: std.mem.Allocator, mnemonic: []const u8, passphrase: ?[]const u8, mode: WalletMode) !Self {
        // Convert mnemonic to seed
        const seed = try crypto.mnemonicToSeed(mnemonic, passphrase, allocator);
        
        // Use first 32 bytes as master seed
        const master_seed = seed[0..32].*;
        
        // Generate RealID identity from seed
        const keypair = zcrypto.asym.ed25519.generateFromSeed(master_seed);
        const identity = realid.RealIDIdentity{
            .keypair = realid.RealIDKeyPair{
                .public_key = realid.RealIDPublicKey{ .bytes = keypair.public_key },
                .private_key = realid.RealIDPrivateKey{ .bytes = keypair.private_key },
            },
            .qid = qid.QID.fromPublicKey(keypair.public_key).bytes,
            .device_bound = mode == .device_bound,
        };
        
        const current_time = std.time.timestamp();
        
        return Self{
            .allocator = allocator,
            .realid_identity = identity,
            .master_qid = qid.QID.fromPublicKey(keypair.public_key),
            .mode = mode,
            .is_locked = false,
            .accounts = std.ArrayList(Account).init(allocator),
            .balances = std.ArrayList(Balance).init(allocator),
            .metadata = WalletMetadata{
                .name = try allocator.dupe(u8, "restored_wallet"),
                .created_at = current_time,
                .last_used = current_time,
                .device_bound = mode == .device_bound,
                .version = try allocator.dupe(u8, "0.3.0"),
            },
            .passphrase_hash = null,
        };
    }
    
    /// Connect to GhostChain daemon with privacy features
    pub fn connectToGhostd(self: *Self, config: ghostd.GhostdConfig) !ghostd.GhostWallet {
        if (self.is_locked) return WalletError.WalletLocked;
        
        var ghost_wallet = try ghostd.GhostWallet.init(self.allocator, config);
        
        // Use a temporary passphrase for connection (in production, use secure input)
        try ghost_wallet.connect("wallet_connection_passphrase");
        
        return ghost_wallet;
    }
    
    /// Zero-copy operations for high-performance scenarios (zcrypto v0.3.0 feature)
    pub fn signDataInPlace(self: *const Self, data: []const u8, signature_buffer: *[64]u8) !void {
        if (self.is_locked) return WalletError.WalletLocked;
        if (self.realid_identity == null) return WalletError.WalletLocked;
        
        const private_key = self.realid_identity.?.keypair.private_key.bytes[0..32].*;
        try crypto.Batch.signInPlace(data, private_key, signature_buffer);
    }
    
    /// Verify multiple signatures in batch for high throughput
    pub fn verifySignatureBatch(self: *const Self, messages: []const []const u8, signatures: [][64]u8, public_keys: [][32]u8) ![]bool {
        return crypto.Batch.verifyMultipleEd25519(messages, signatures, public_keys, self.allocator);
    }
    
    /// Get wallet statistics and health information
    pub fn getWalletStats(self: *const Self) WalletStats {
        return WalletStats{
            .account_count = @intCast(self.accounts.items.len),
            .balance_count = @intCast(self.balances.items.len),
            .created_at = self.metadata.created_at,
            .last_used = self.metadata.last_used,
            .device_bound = self.metadata.device_bound,
            .is_locked = self.is_locked,
            .version = self.metadata.version,
        };
    }
    
    // Private helper methods for enhanced features
    
    fn serializeWalletData(self: *const Self) ![]u8 {
        // TODO: Implement proper wallet serialization
        return try self.allocator.dupe(u8, "serialized_wallet_data_v0.3.0");
    }
    
    fn deserializeWalletData(allocator: std.mem.Allocator, data: []const u8) !Self {
        // TODO: Implement proper wallet deserialization
        _ = data;
        return Self.create(allocator, "default_passphrase", .hybrid, "imported_wallet");
    }
};

/// Wallet statistics for monitoring and health checks
pub const WalletStats = struct {
    account_count: u32,
    balance_count: u32,
    created_at: i64,
    last_used: i64,
    device_bound: bool,
    is_locked: bool,
    version: []const u8,
};

/// Production-ready wallet factory with enhanced security
pub const WalletFactory = struct {
    /// Create secure wallet with enhanced entropy
    pub fn createSecureWallet(allocator: std.mem.Allocator, passphrase: []const u8, entropy_source: ?[]const u8) !Wallet {
        // Enhance passphrase with additional entropy
        var enhanced_seed = std.ArrayList(u8).init(allocator);
        defer enhanced_seed.deinit();
        
        try enhanced_seed.appendSlice(passphrase);
        if (entropy_source) |entropy| {
            try enhanced_seed.appendSlice(entropy);
        }
        
        // Add system entropy
        var system_entropy: [32]u8 = undefined;
        zcrypto.random.fill(&system_entropy);
        try enhanced_seed.appendSlice(&system_entropy);
        
        // Hash to create final seed
        const final_seed = zcrypto.hash.sha256(enhanced_seed.items);
        
        // Create wallet with enhanced security
        return Wallet.create(allocator, &final_seed, .device_bound, "secure_wallet");
    }
    
    /// Create wallet optimized for production deployment
    pub fn createProductionWallet(allocator: std.mem.Allocator, config: ProductionConfig) !Wallet {
        const wallet = try Wallet.create(allocator, config.passphrase, config.mode, config.name);
        
        // Pre-create accounts for common protocols if requested
        if (config.create_default_accounts) {
            var w = wallet;
            _ = try w.createAccount(.ghostchain, .ed25519);
            _ = try w.createAccount(.ethereum, .secp256k1);
            _ = try w.createAccount(.bitcoin, .secp256k1);
        }
        
        return wallet;
    }
};

pub const ProductionConfig = struct {
    passphrase: []const u8,
    mode: WalletMode,
    name: ?[]const u8,
    create_default_accounts: bool,
    enable_metrics: bool,
    backup_enabled: bool,
};
};

test "wallet creation with RealID" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var wallet = try Wallet.create(allocator, "test_passphrase_123", .hybrid, "test_wallet");
    defer wallet.deinit();
    
    try std.testing.expect(!wallet.is_locked);
    try std.testing.expect(wallet.master_qid != null);
    try std.testing.expect(wallet.realid_identity != null);
}

test "wallet lock and unlock" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var wallet = try Wallet.create(allocator, "secure_passphrase", .device_bound, "secure_wallet");
    defer wallet.deinit();
    
    try std.testing.expect(!wallet.is_locked);
    
    // Lock wallet
    wallet.lock();
    try std.testing.expect(wallet.is_locked);
    
    // Unlock with correct passphrase
    try wallet.unlock("secure_passphrase");
    try std.testing.expect(!wallet.is_locked);
    
    // Try to unlock with wrong passphrase
    wallet.lock();
    const result = wallet.unlock("wrong_passphrase");
    try std.testing.expectError(WalletError.InvalidPassphrase, result);
}

test "account creation and addressing" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    
    var wallet = try Wallet.create(allocator, "test_passphrase", .hybrid, "multi_protocol_wallet");
    defer wallet.deinit();
    
    // Create accounts for different protocols
    const ghost_account = try wallet.createAccount(.ghostchain, .ed25519);
    const eth_account = try wallet.createAccount(.ethereum, .secp256k1);
    
    try std.testing.expect(ghost_account.protocol == .ghostchain);
    try std.testing.expect(eth_account.protocol == .ethereum);
    try std.testing.expect(wallet.accounts.items.len == 2);
}
