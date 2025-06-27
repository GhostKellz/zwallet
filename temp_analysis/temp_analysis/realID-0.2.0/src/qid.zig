const std = @import("std");
const zcrypto = @import("zcrypto");
const types = @import("types.zig");

const RealIDPublicKey = types.RealIDPublicKey;
const QID = types.QID;

// IPv6 prefix for RealID QIDs (RFC 4193 Unique Local IPv6 Unicast Addresses)
const REALID_IPV6_PREFIX = [_]u8{ 0xfd, 0x00 }; // fd00::/8 prefix

/// Generate a stateless IPv6 QID from a RealID public key
pub fn realid_qid_from_pubkey(public_key: RealIDPublicKey) QID {
    // Hash the public key with a RealID-specific salt using SHA-256
    const salt_prefix = "RealID-QID-v1";
    const input_data = salt_prefix ++ public_key.bytes;
    const hash = zcrypto.hash.sha256(input_data);
    
    // Create IPv6 address from hash
    var qid_bytes: [16]u8 = undefined;
    
    // Set the ULA prefix (fd00::/8)
    qid_bytes[0] = REALID_IPV6_PREFIX[0];
    qid_bytes[1] = REALID_IPV6_PREFIX[1];
    
    // Use first 14 bytes of hash for the rest of the address
    @memcpy(qid_bytes[2..16], hash[0..14]);
    
    return QID{ .bytes = qid_bytes };
}

/// Convert QID to string representation (IPv6 format)
pub fn qid_to_string(qid: QID, buffer: []u8) ![]u8 {
    if (buffer.len < 39) { // IPv6 addresses can be up to 39 characters
        return error.BufferTooSmall;
    }

    const bytes = qid.bytes;
    return std.fmt.bufPrint(buffer, "{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}:{x:0>2}{x:0>2}", .{
        bytes[0],  bytes[1],  bytes[2],  bytes[3],
        bytes[4],  bytes[5],  bytes[6],  bytes[7],
        bytes[8],  bytes[9],  bytes[10], bytes[11],
        bytes[12], bytes[13], bytes[14], bytes[15],
    });
}

/// Parse QID from string representation
pub fn qid_from_string(qid_str: []const u8) !QID {
    // This is a simplified parser - in production you'd want more robust parsing
    var qid_bytes: [16]u8 = undefined;

    // Remove colons and parse hex
    var hex_str: [32]u8 = undefined;
    var hex_idx: usize = 0;

    for (qid_str) |char| {
        if (char != ':') {
            if (hex_idx >= hex_str.len) return error.InvalidFormat;
            hex_str[hex_idx] = char;
            hex_idx += 1;
        }
    }

    if (hex_idx != 32) return error.InvalidFormat;

    // Convert hex string to bytes
    for (0..16) |i| {
        const hex_pair = hex_str[i * 2 .. i * 2 + 2];
        qid_bytes[i] = std.fmt.parseInt(u8, hex_pair, 16) catch return error.InvalidFormat;
    }

    return QID{ .bytes = qid_bytes };
}

/// Check if a QID is a valid RealID QID (has correct prefix)
pub fn is_valid_realid_qid(qid: QID) bool {
    return qid.bytes[0] == REALID_IPV6_PREFIX[0] and qid.bytes[1] == REALID_IPV6_PREFIX[1];
}
