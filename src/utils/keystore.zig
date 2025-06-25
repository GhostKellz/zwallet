//! Encrypted keystore for secure key storage
//! Provides JSON keystore format with Argon2 key derivation

const std = @import("std");
const zcrypto = @import("zcrypto");
const Allocator = std.mem.Allocator;
const crypto = @import("crypto.zig");

pub const KeystoreError = error{
    InvalidPassword,
    CorruptedKeystore,
    UnsupportedVersion,
    DecryptionFailed,
    EncryptionFailed,
    InvalidFormat,
    SerializationFailed,
};

pub const KeystoreVersion = enum(u8) {
    v1 = 1,
    v2 = 2,
    v3 = 3, // Updated version with zcrypto
};

pub const EncryptionParams = struct {
    cipher: []const u8,
    salt: [32]u8,
    iv: [16]u8,
    iterations: u32,
    memory_cost: u32,
    parallelism: u32,
};

pub const Keystore = struct {
    version: KeystoreVersion,
    id: [16]u8, // UUID
    address: ?[]const u8,
    crypto_params: EncryptionParams,
    ciphertext: []const u8,
    mac: [32]u8, // HMAC for integrity
    
    allocator: Allocator,
    
    pub fn init(allocator: Allocator) Keystore {
        var id: [16]u8 = undefined;
        zcrypto.rand.fillBytes(&id);
        
        const salt = zcrypto.rand.generateSalt(32);
        var iv: [16]u8 = undefined;
        zcrypto.rand.fillBytes(&iv);
        
        return Keystore{
            .version = .v3,
            .id = id,
            .address = null,
            .crypto_params = EncryptionParams{
                .cipher = "aes-256-gcm",
                .salt = salt,
                .iv = iv,
                .iterations = 600000, // Argon2 iterations
                .memory_cost = 65536,  // 64 MB
                .parallelism = 4,
            },
            .ciphertext = &[_]u8{},
            .mac = [_]u8{0} ** 32,
            .allocator = allocator,
        };
    }
    
    pub fn deinit(self: *Keystore) void {
        if (self.address) |addr| {
            self.allocator.free(addr);
        }
        if (self.ciphertext.len > 0) {
            // Securely zero out ciphertext before freeing
            zcrypto.util.secureZero(@constCast(self.ciphertext));
            self.allocator.free(@constCast(self.ciphertext));
        }
    }
    
    /// Encrypt and store a keypair
    pub fn encryptKeypair(self: *Keystore, keypair: *const crypto.KeyPair, password: []const u8, address: ?[]const u8) !void {
        // Derive encryption key from password using Argon2
        const derived_key = try self.deriveKey(password);
        defer @memset(&derived_key, 0); // Clear derived key
        
        // Serialize keypair
        const plaintext = try self.serializeKeypair(keypair);
        defer {
            @memset(plaintext, 0);
            self.allocator.free(plaintext);
        }
        
        // Encrypt plaintext with AES-256-GCM
        const ciphertext = try self.encrypt(plaintext, &derived_key);
        
        // Calculate MAC for additional integrity check
        const mac = try self.calculateMac(&derived_key, ciphertext);
        
        // Store encrypted data
        if (self.ciphertext.len > 0) {
            self.allocator.free(@constCast(self.ciphertext));
        }
        self.ciphertext = ciphertext;
        self.mac = mac;
        
        // Store address
        if (address) |addr| {
            if (self.address) |old_addr| {
                self.allocator.free(old_addr);
            }
            self.address = try self.allocator.dupe(u8, addr);
        }
    }
    
    /// Decrypt and restore a keypair
    pub fn decryptKeypair(self: *const Keystore, password: []const u8) !crypto.KeyPair {
        // Derive decryption key
        const derived_key = try self.deriveKey(password);
        defer @memset(@constCast(&derived_key), 0);
        
        // Verify MAC
        const expected_mac = try self.calculateMac(&derived_key, self.ciphertext);
        if (!std.mem.eql(u8, &self.mac, &expected_mac)) {
            return KeystoreError.InvalidPassword;
        }
        
        // Decrypt ciphertext
        const plaintext = try self.decrypt(self.ciphertext, &derived_key);
        defer {
            @memset(plaintext, 0);
            self.allocator.free(plaintext);
        }
        
        // Deserialize keypair
        return try self.deserializeKeypair(plaintext);
    }
    
    /// Save keystore to file
    pub fn saveToFile(self: *const Keystore, path: []const u8) !void {
        const json = try self.toJson();
        defer self.allocator.free(json);
        
        const file = try std.fs.cwd().createFile(path, .{ .mode = 0o600 }); // Restrictive permissions
        defer file.close();
        
        try file.writeAll(json);
    }
    
    /// Load keystore from file
    pub fn loadFromFile(allocator: Allocator, path: []const u8) !Keystore {
        const file = try std.fs.cwd().openFile(path, .{});
        defer file.close();
        
        const content = try file.readToEndAlloc(allocator, 1024 * 1024); // Max 1MB
        defer allocator.free(content);
        
        return try fromJson(allocator, content);
    }
    
    /// Convert keystore to JSON
    pub fn toJson(self: *const Keystore) ![]u8 {
        var json = std.ArrayList(u8).init(self.allocator);
        defer json.deinit();
        
        const writer = json.writer();
        
        // Write JSON manually for control over format
        try writer.writeAll("{\n");
        try writer.print("  \"version\": {},\n", .{@intFromEnum(self.version)});
        
        // UUID formatting
        try writer.writeAll("  \"id\": \"");
        try self.writeHex(writer, &self.id);
        try writer.writeAll("\",\n");
        
        // Address
        try writer.print("  \"address\": \"{s}\",\n", .{self.address orelse ""});
        
        // Crypto section
        try writer.writeAll("  \"crypto\": {\n");
        try writer.print("    \"cipher\": \"{s}\",\n", .{self.crypto_params.cipher});
        
        // Cipher params
        try writer.writeAll("    \"cipherparams\": {\n");
        try writer.writeAll("      \"iv\": \"");
        try self.writeHex(writer, &self.crypto_params.iv);
        try writer.writeAll("\"\n    },\n");
        
        // Ciphertext
        try writer.writeAll("    \"ciphertext\": \"");
        try self.writeHex(writer, self.ciphertext);
        try writer.writeAll("\",\n");
        
        // KDF
        try writer.writeAll("    \"kdf\": \"argon2id\",\n");
        try writer.writeAll("    \"kdfparams\": {\n");
        try writer.writeAll("      \"salt\": \"");
        try self.writeHex(writer, &self.crypto_params.salt);
        try writer.writeAll("\",\n");
        try writer.print("      \"iterations\": {},\n", .{self.crypto_params.iterations});
        try writer.print("      \"memoryCost\": {},\n", .{self.crypto_params.memory_cost});
        try writer.print("      \"parallelism\": {}\n", .{self.crypto_params.parallelism});
        try writer.writeAll("    },\n");
        
        // MAC
        try writer.writeAll("    \"mac\": \"");
        try self.writeHex(writer, &self.mac);
        try writer.writeAll("\"\n");
        
        try writer.writeAll("  }\n");
        try writer.writeAll("}");
        
        return json.toOwnedSlice();
    }
    
    /// Create keystore from JSON
    pub fn fromJson(allocator: Allocator, json: []const u8) !Keystore {
        var parser = std.json.Parser.init(allocator, false);
        defer parser.deinit();
        
        var tree = try parser.parse(json);
        defer tree.deinit();
        
        const root = tree.root.Object;
        
        // Parse version
        const version_num = root.get("version") orelse return KeystoreError.InvalidFormat;
        const version = try std.meta.intToEnum(KeystoreVersion, @intCast(version_num.Integer));
        
        // Parse ID
        const id_str = root.get("id") orelse return KeystoreError.InvalidFormat;
        const id = try parseHex([16]u8, id_str.String);
        
        // Parse address
        const address_str = root.get("address") orelse return KeystoreError.InvalidFormat;
        const address = if (address_str.String.len > 0) 
            try allocator.dupe(u8, address_str.String) 
        else 
            null;
        
        // Parse crypto section
        const crypto_obj = root.get("crypto") orelse return KeystoreError.InvalidFormat;
        const crypto_data = crypto_obj.Object;
        
        // Parse cipher
        const cipher_str = crypto_data.get("cipher") orelse return KeystoreError.InvalidFormat;
        
        // Parse cipher params
        const cipherparams = crypto_data.get("cipherparams") orelse return KeystoreError.InvalidFormat;
        const iv_str = cipherparams.Object.get("iv") orelse return KeystoreError.InvalidFormat;
        const iv = try parseHex([16]u8, iv_str.String);
        
        // Parse ciphertext
        const ciphertext_str = crypto_data.get("ciphertext") orelse return KeystoreError.InvalidFormat;
        const ciphertext = try parseHexAlloc(allocator, ciphertext_str.String);
        
        // Parse KDF params
        const kdfparams = crypto_data.get("kdfparams") orelse return KeystoreError.InvalidFormat;
        const kdf_obj = kdfparams.Object;
        
        const salt_str = kdf_obj.get("salt") orelse return KeystoreError.InvalidFormat;
        const salt = try parseHex([32]u8, salt_str.String);
        
        const iterations = kdf_obj.get("iterations") orelse return KeystoreError.InvalidFormat;
        const memory_cost = kdf_obj.get("memoryCost") orelse return KeystoreError.InvalidFormat;
        const parallelism = kdf_obj.get("parallelism") orelse return KeystoreError.InvalidFormat;
        
        // Parse MAC
        const mac_str = crypto_data.get("mac") orelse return KeystoreError.InvalidFormat;
        const mac = try parseHex([32]u8, mac_str.String);
        
        return Keystore{
            .version = version,
            .id = id,
            .address = address,
            .crypto_params = EncryptionParams{
                .cipher = cipher_str.String,
                .salt = salt,
                .iv = iv,
                .iterations = @intCast(iterations.Integer),
                .memory_cost = @intCast(memory_cost.Integer),
                .parallelism = @intCast(parallelism.Integer),
            },
            .ciphertext = ciphertext,
            .mac = mac,
            .allocator = allocator,
        };
    }
    
    // Helper functions
    
    fn deriveKey(self: *const Keystore, password: []const u8) ![32]u8 {
        // Use Argon2id from zcrypto for secure password derivation
        return try zcrypto.kdf.argon2id(self.allocator, password, self.crypto_params.salt, 32);
    }
    
    fn encrypt(self: *const Keystore, plaintext: []const u8, key: *const [32]u8) ![]u8 {
        // Use zcrypto's simplified AES-GCM API
        return try zcrypto.sym.encryptAesGcm(self.allocator, plaintext, key);
    }
    
    fn decrypt(self: *const Keystore, ciphertext: []const u8, key: *const [32]u8) ![]u8 {
        // Use zcrypto's simplified AES-GCM API
        return zcrypto.sym.decryptAesGcm(self.allocator, ciphertext, key) catch KeystoreError.DecryptionFailed;
    }
    
    fn calculateMac(self: *const Keystore, key: *const [32]u8, data: []const u8) ![32]u8 {
        _ = self;
        
        // Use zcrypto's HMAC-SHA256
        return zcrypto.auth.hmac.sha256(data, key.*);
    }
    
    fn serializeKeypair(self: *const Keystore, keypair: *const crypto.KeyPair) ![]u8 {
        // Enhanced serialization with version byte
        const serialized = try self.allocator.alloc(u8, 2 + 32 + 64); // version + key_type + public + private
        
        serialized[0] = 1; // Serialization version
        serialized[1] = @intFromEnum(keypair.key_type);
        @memcpy(serialized[2..34], &keypair.public_key);
        @memcpy(serialized[34..98], &keypair.private_key);
        
        return serialized;
    }
    
    fn deserializeKeypair(self: *const Keystore, data: []const u8) !crypto.KeyPair {
        _ = self;
        
        if (data.len != 98) {
            return KeystoreError.InvalidFormat;
        }
        
        // Check serialization version
        if (data[0] != 1) {
            return KeystoreError.UnsupportedVersion;
        }
        
        const key_type = std.meta.intToEnum(crypto.KeyType, data[1]) catch return KeystoreError.InvalidFormat;
        
        var keypair = crypto.KeyPair{
            .key_type = key_type,
            .public_key = undefined,
            .private_key = undefined,
        };
        
        @memcpy(&keypair.public_key, data[2..34]);
        @memcpy(&keypair.private_key, data[34..98]);
        
        return keypair;
    }
    
    fn writeHex(self: *const Keystore, writer: anytype, bytes: []const u8) !void {
        _ = self;
        const hex_chars = "0123456789abcdef";
        for (bytes) |byte| {
            try writer.writeByte(hex_chars[byte >> 4]);
            try writer.writeByte(hex_chars[byte & 0x0F]);
        }
    }
    
    fn parseHex(comptime T: type, hex: []const u8) !T {
        var result: T = undefined;
        const bytes = @as([]u8, &result);
        
        if (hex.len != bytes.len * 2) {
            return KeystoreError.InvalidFormat;
        }
        
        var i: usize = 0;
        while (i < bytes.len) : (i += 1) {
            const high = try charToNibble(hex[i * 2]);
            const low = try charToNibble(hex[i * 2 + 1]);
            bytes[i] = (high << 4) | low;
        }
        
        return result;
    }
    
    fn parseHexAlloc(allocator: Allocator, hex: []const u8) ![]u8 {
        if (hex.len % 2 != 0) {
            return KeystoreError.InvalidFormat;
        }
        
        const bytes = try allocator.alloc(u8, hex.len / 2);
        errdefer allocator.free(bytes);
        
        var i: usize = 0;
        while (i < bytes.len) : (i += 1) {
            const high = try charToNibble(hex[i * 2]);
            const low = try charToNibble(hex[i * 2 + 1]);
            bytes[i] = (high << 4) | low;
        }
        
        return bytes;
    }
    
    fn charToNibble(c: u8) !u4 {
        return switch (c) {
            '0'...'9' => @intCast(c - '0'),
            'a'...'f' => @intCast(c - 'a' + 10),
            'A'...'F' => @intCast(c - 'A' + 10),
            else => KeystoreError.InvalidFormat,
        };
    }
};

test "keystore creation" {
    var keystore = Keystore.init(std.testing.allocator);
    defer keystore.deinit();
    
    try std.testing.expect(keystore.version == .v3);
}

test "keystore encryption/decryption" {
    var keystore = Keystore.init(std.testing.allocator);
    defer keystore.deinit();
    
    var keypair = try crypto.KeyPair.generate(.ed25519);
    defer keypair.deinit();
    
    try keystore.encryptKeypair(&keypair, "test_password", "test_address");
    
    const decrypted = try keystore.decryptKeypair("test_password");
    try std.testing.expectEqualSlices(u8, &keypair.public_key, &decrypted.public_key);
    try std.testing.expectEqualSlices(u8, &keypair.private_key, &decrypted.private_key);
}

test "keystore json serialization" {
    var keystore = Keystore.init(std.testing.allocator);
    defer keystore.deinit();
    
    var keypair = try crypto.KeyPair.generate(.secp256k1);
    defer keypair.deinit();
    
    try keystore.encryptKeypair(&keypair, "secure_password", "0x1234567890123456789012345678901234567890");
    
    const json = try keystore.toJson();
    defer std.testing.allocator.free(json);
    
    var loaded_keystore = try Keystore.fromJson(std.testing.allocator, json);
    defer loaded_keystore.deinit();
    
    try std.testing.expectEqual(keystore.version, loaded_keystore.version);
    try std.testing.expectEqualSlices(u8, &keystore.id, &loaded_keystore.id);
}