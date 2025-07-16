//! Shroud-based identity and privacy management for ZWallet
//! Provides ephemeral identities, privacy tokens, and access control

const std = @import("std");
const Allocator = std.mem.Allocator;
const shroud = @import("shroud");
const zcrypto = @import("zcrypto");

pub const IdentityError = error{
    InvalidIdentity,
    TokenGenerationFailed,
    GuardianPermissionDenied,
    IdentityExpired,
    InvalidAccessToken,
    PrivacyConstraintViolation,
};

pub const IdentityMode = enum {
    persistent,   // Long-lived identity
    ephemeral,    // Short-lived privacy identity
    anonymous,    // Zero-knowledge anonymous identity
};

/// Privacy-preserving identity with Shroud integration
pub const ShroudIdentity = struct {
    allocator: Allocator,
    mode: IdentityMode,
    identity: shroud.identity.Identity,
    guardian: ?shroud.guardian.Guardian,
    access_tokens: std.ArrayList(shroud.access_token.AccessToken),
    created_at: i64,
    expires_at: ?i64,

    pub fn init(allocator: Allocator, mode: IdentityMode) !ShroudIdentity {
        const identity = try shroud.identity.Identity.generate(allocator);
        
        return ShroudIdentity{
            .allocator = allocator,
            .mode = mode,
            .identity = identity,
            .guardian = null,
            .access_tokens = std.ArrayList(shroud.access_token.AccessToken).init(allocator),
            .created_at = std.time.timestamp(),
            .expires_at = switch (mode) {
                .ephemeral => std.time.timestamp() + 3600, // 1 hour
                .anonymous => std.time.timestamp() + 300,  // 5 minutes
                .persistent => null,
            },
        };
    }

    pub fn deinit(self: *ShroudIdentity) void {
        self.access_tokens.deinit();
        self.identity.deinit();
        if (self.guardian) |*guardian| {
            guardian.deinit();
        }
    }

    /// Generate a new ephemeral identity for privacy
    pub fn generateEphemeralIdentity(allocator: Allocator) !ShroudIdentity {
        return ShroudIdentity.init(allocator, .ephemeral);
    }

    /// Create access token for specific operation
    pub fn createAccessToken(self: *ShroudIdentity, operation: []const u8, duration: i64) !shroud.access_token.AccessToken {
        if (self.isExpired()) {
            return IdentityError.IdentityExpired;
        }

        const token = try shroud.access_token.AccessToken.create(
            self.allocator,
            &self.identity,
            operation,
            duration
        );

        try self.access_tokens.append(token);
        return token;
    }

    /// Check if identity has expired
    pub fn isExpired(self: *const ShroudIdentity) bool {
        if (self.expires_at) |expires| {
            return std.time.timestamp() > expires;
        }
        return false;
    }

    /// Sign data with privacy-preserving signature
    pub fn signWithPrivacy(self: *ShroudIdentity, data: []const u8) ![]u8 {
        if (self.isExpired()) {
            return IdentityError.IdentityExpired;
        }

        return self.identity.sign(data);
    }

    /// Verify that this identity has permission for operation
    pub fn verifyPermission(self: *ShroudIdentity, operation: []const u8) !bool {
        if (self.guardian) |*guardian| {
            return guardian.checkPermission(operation);
        }
        return true; // No guardian means no restrictions
    }

    /// Get DID (Decentralized Identifier) for this identity
    pub fn getDID(self: *const ShroudIdentity) []const u8 {
        return self.identity.getDID();
    }

    /// Rotate identity (for privacy)
    pub fn rotate(self: *ShroudIdentity) !void {
        if (self.mode == .persistent) {
            return IdentityError.PrivacyConstraintViolation;
        }

        // Clear old tokens
        self.access_tokens.clearAndFree();
        
        // Generate new identity
        self.identity.deinit();
        self.identity = try shroud.identity.Identity.generate(self.allocator);
        
        // Update timestamps
        self.created_at = std.time.timestamp();
        if (self.expires_at) |_| {
            self.expires_at = switch (self.mode) {
                .ephemeral => std.time.timestamp() + 3600,
                .anonymous => std.time.timestamp() + 300,
                .persistent => null,
            };
        }
    }
};

/// Guardian-based access control system
pub const AccessGuardian = struct {
    allocator: Allocator,
    guardian: shroud.guardian.Guardian,
    policies: std.ArrayList(AccessPolicy),

    pub const AccessPolicy = struct {
        operation: []const u8,
        required_role: []const u8,
        max_amount: ?i64,
        time_restriction: ?TimeRestriction,
        
        pub const TimeRestriction = struct {
            start_hour: u8,
            end_hour: u8,
            allowed_days: u8, // Bitmask: Mon=1, Tue=2, Wed=4, etc.
        };
    };

    pub fn init(allocator: Allocator) !AccessGuardian {
        const guardian = try shroud.guardian.Guardian.init(allocator);
        
        return AccessGuardian{
            .allocator = allocator,
            .guardian = guardian,
            .policies = std.ArrayList(AccessPolicy).init(allocator),
        };
    }

    pub fn deinit(self: *AccessGuardian) void {
        self.policies.deinit();
        self.guardian.deinit();
    }

    /// Add access policy
    pub fn addPolicy(self: *AccessGuardian, policy: AccessPolicy) !void {
        try self.policies.append(policy);
    }

    /// Check if operation is allowed
    pub fn checkAccess(self: *AccessGuardian, operation: []const u8, role: []const u8, amount: ?i64) !bool {
        for (self.policies.items) |policy| {
            if (std.mem.eql(u8, policy.operation, operation)) {
                // Check role
                if (!std.mem.eql(u8, policy.required_role, role)) {
                    return false;
                }
                
                // Check amount limits
                if (policy.max_amount) |max| {
                    if (amount) |amt| {
                        if (amt > max) return false;
                    }
                }
                
                // Check time restrictions
                if (policy.time_restriction) |time_restrict| {
                    const now = std.time.timestamp();
                    const dt = std.time.epoch.EpochSeconds{ .secs = @intCast(now) };
                    const day_seconds = dt.getDaySeconds();
                    const hour = @divTrunc(day_seconds, 3600);
                    
                    if (hour < time_restrict.start_hour or hour >= time_restrict.end_hour) {
                        return false;
                    }
                }
                
                return true;
            }
        }
        
        return false; // No policy found means deny
    }
};

test "shroud identity creation" {
    var identity = try ShroudIdentity.init(std.testing.allocator, .ephemeral);
    defer identity.deinit();
    
    try std.testing.expect(!identity.isExpired());
    try std.testing.expect(identity.getDID().len > 0);
}

test "access token generation" {
    var identity = try ShroudIdentity.init(std.testing.allocator, .persistent);
    defer identity.deinit();
    
    const token = try identity.createAccessToken("send_transaction", 3600);
    try std.testing.expect(token.isValid());
}

test "guardian access control" {
    var guardian = try AccessGuardian.init(std.testing.allocator);
    defer guardian.deinit();
    
    const policy = AccessGuardian.AccessPolicy{
        .operation = "send_transaction",
        .required_role = "user",
        .max_amount = 1000,
        .time_restriction = null,
    };
    
    try guardian.addPolicy(policy);
    
    const allowed = try guardian.checkAccess("send_transaction", "user", 500);
    try std.testing.expect(allowed);
    
    const denied = try guardian.checkAccess("send_transaction", "user", 2000);
    try std.testing.expect(!denied);
}