//! Ethereum RPC client for ENS resolution and transaction broadcasting
//! Supports both HTTP and WebSocket connections using TokioZ

const std = @import("std");
const tokioz = @import("tokioz");
const zcrypto = @import("zcrypto");
const Allocator = std.mem.Allocator;

pub const RpcError = error{
    NetworkError,
    InvalidResponse,
    InvalidMethod,
    ServerError,
    Timeout,
    ConnectionFailed,
    InvalidEndpoint,
};

pub const RpcRequest = struct {
    jsonrpc: []const u8 = "2.0",
    method: []const u8,
    params: ?std.json.Value,
    id: u64,
};

pub const RpcResponse = struct {
    jsonrpc: []const u8,
    result: ?std.json.Value,
    @"error": ?RpcErrorData,
    id: u64,
};

pub const RpcErrorData = struct {
    code: i32,
    message: []const u8,
    data: ?std.json.Value,
};

pub const EthereumRpc = struct {
    allocator: Allocator,
    endpoint: []const u8,
    runtime: *tokioz.Runtime,
    request_id: std.atomic.Value(u64),
    
    pub fn init(allocator: Allocator, endpoint: []const u8) !EthereumRpc {
        const runtime = try tokioz.Runtime.init(allocator);
        
        return EthereumRpc{
            .allocator = allocator,
            .endpoint = try allocator.dupe(u8, endpoint),
            .runtime = runtime,
            .request_id = std.atomic.Value(u64).init(1),
        };
    }
    
    pub fn deinit(self: *EthereumRpc) void {
        self.allocator.free(self.endpoint);
        self.runtime.deinit();
    }
    
    /// Call ETH RPC method
    pub fn call(self: *EthereumRpc, method: []const u8, params: ?std.json.Value) !std.json.Value {
        const req_id = self.request_id.fetchAdd(1, .monotonic);
        
        const request = RpcRequest{
            .method = method,
            .params = params,
            .id = req_id,
        };
        
        // Serialize request to JSON
        var json_buf = std.ArrayList(u8).init(self.allocator);
        defer json_buf.deinit();
        
        try std.json.stringify(request, .{}, json_buf.writer());
        
        // Create HTTP request using TokioZ
        const client = try tokioz.http.Client.init(self.runtime);
        defer client.deinit();
        
        var headers = tokioz.http.Headers.init(self.allocator);
        defer headers.deinit();
        try headers.append("Content-Type", "application/json");
        
        const response = try client.post(self.endpoint, json_buf.items, headers);
        defer response.deinit();
        
        if (response.status != 200) {
            return RpcError.ServerError;
        }
        
        // Parse response
        var parser = std.json.Parser.init(self.allocator, false);
        defer parser.deinit();
        
        var tree = try parser.parse(response.body);
        defer tree.deinit();
        
        const rpc_response = try parseRpcResponse(tree.root);
        
        if (rpc_response.@"error") |err| {
            std.log.err("RPC error {}: {s}", .{ err.code, err.message });
            return RpcError.ServerError;
        }
        
        if (rpc_response.result) |result| {
            // Clone the result to return it
            return try cloneJsonValue(self.allocator, result);
        }
        
        return RpcError.InvalidResponse;
    }
    
    /// Batch RPC call for efficiency
    pub fn batchCall(self: *EthereumRpc, requests: []const RpcRequest) ![]RpcResponse {
        var json_buf = std.ArrayList(u8).init(self.allocator);
        defer json_buf.deinit();
        
        try json_buf.append('[');
        for (requests, 0..) |request, i| {
            if (i > 0) try json_buf.append(',');
            try std.json.stringify(request, .{}, json_buf.writer());
        }
        try json_buf.append(']');
        
        const client = try tokioz.http.Client.init(self.runtime);
        defer client.deinit();
        
        var headers = tokioz.http.Headers.init(self.allocator);
        defer headers.deinit();
        try headers.append("Content-Type", "application/json");
        
        const response = try client.post(self.endpoint, json_buf.items, headers);
        defer response.deinit();
        
        if (response.status != 200) {
            return RpcError.ServerError;
        }
        
        var parser = std.json.Parser.init(self.allocator, false);
        defer parser.deinit();
        
        var tree = try parser.parse(response.body);
        defer tree.deinit();
        
        // Parse batch response
        if (tree.root != .array) {
            return RpcError.InvalidResponse;
        }
        
        var results = try self.allocator.alloc(RpcResponse, tree.root.array.items.len);
        for (tree.root.array.items, 0..) |item, i| {
            results[i] = try parseRpcResponse(item);
        }
        
        return results;
    }
    
    /// Resolve ENS name to address
    pub fn resolveENS(self: *EthereumRpc, name: []const u8) ![]const u8 {
        // ENS Registry address on mainnet
        const ens_registry = "0x00000000000C2E074eC69A0dFb2997BA6C7d2e1e";
        
        // Calculate namehash
        const namehash = try calculateNamehash(self.allocator, name);
        defer self.allocator.free(namehash);
        
        // First, get the resolver address
        const resolver_data = try std.fmt.allocPrint(self.allocator, "0x0178b8bf{s}", .{
            std.fmt.fmtSliceHexLower(namehash),
        });
        defer self.allocator.free(resolver_data);
        
        var call_params = std.json.ObjectMap.init(self.allocator);
        defer call_params.deinit();
        try call_params.put("to", .{ .string = ens_registry });
        try call_params.put("data", .{ .string = resolver_data });
        
        const resolver_result = try self.call("eth_call", .{ 
            .array = &[_]std.json.Value{
                .{ .object = call_params },
                .{ .string = "latest" },
            },
        });
        defer if (resolver_result == .string) self.allocator.free(resolver_result.string);
        
        if (resolver_result != .string or resolver_result.string.len < 66) {
            return RpcError.InvalidResponse;
        }
        
        // Extract resolver address (last 40 hex chars)
        const resolver_hex = resolver_result.string[26..66];
        const resolver_addr = try std.fmt.allocPrint(self.allocator, "0x{s}", .{resolver_hex});
        defer self.allocator.free(resolver_addr);
        
        // Now call the resolver's addr() function
        const addr_data = try std.fmt.allocPrint(self.allocator, "0x3b3b57de{s}", .{
            std.fmt.fmtSliceHexLower(namehash),
        });
        defer self.allocator.free(addr_data);
        
        var addr_params = std.json.ObjectMap.init(self.allocator);
        defer addr_params.deinit();
        try addr_params.put("to", .{ .string = resolver_addr });
        try addr_params.put("data", .{ .string = addr_data });
        
        const addr_result = try self.call("eth_call", .{
            .array = &[_]std.json.Value{
                .{ .object = addr_params },
                .{ .string = "latest" },
            },
        });
        defer if (addr_result == .string) self.allocator.free(addr_result.string);
        
        if (addr_result != .string or addr_result.string.len < 66) {
            return RpcError.InvalidResponse;
        }
        
        // Extract address (last 40 hex chars)
        const address_hex = addr_result.string[26..66];
        return try std.fmt.allocPrint(self.allocator, "0x{s}", .{address_hex});
    }
    
    /// Get account balance
    pub fn getBalance(self: *EthereumRpc, address: []const u8, block: ?[]const u8) !u256 {
        const block_param = block orelse "latest";
        
        const result = try self.call("eth_getBalance", .{
            .array = &[_]std.json.Value{
                .{ .string = address },
                .{ .string = block_param },
            },
        });
        defer if (result == .string) self.allocator.free(result.string);
        
        if (result != .string) {
            return RpcError.InvalidResponse;
        }
        
        // Parse hex string to u256
        return try parseHexInt(u256, result.string);
    }
    
    /// Get current gas price
    pub fn getGasPrice(self: *EthereumRpc) !u256 {
        const result = try self.call("eth_gasPrice", null);
        defer if (result == .string) self.allocator.free(result.string);
        
        if (result != .string) {
            return RpcError.InvalidResponse;
        }
        
        return try parseHexInt(u256, result.string);
    }
    
    /// Estimate gas for transaction
    pub fn estimateGas(self: *EthereumRpc, tx: TransactionRequest) !u256 {
        var tx_obj = std.json.ObjectMap.init(self.allocator);
        defer tx_obj.deinit();
        
        if (tx.from) |from| try tx_obj.put("from", .{ .string = from });
        if (tx.to) |to| try tx_obj.put("to", .{ .string = to });
        if (tx.value) |value| {
            const hex = try std.fmt.allocPrint(self.allocator, "0x{x}", .{value});
            defer self.allocator.free(hex);
            try tx_obj.put("value", .{ .string = hex });
        }
        if (tx.data) |data| try tx_obj.put("data", .{ .string = data });
        
        const result = try self.call("eth_estimateGas", .{
            .array = &[_]std.json.Value{.{ .object = tx_obj }},
        });
        defer if (result == .string) self.allocator.free(result.string);
        
        if (result != .string) {
            return RpcError.InvalidResponse;
        }
        
        return try parseHexInt(u256, result.string);
    }
    
    /// Send raw transaction
    pub fn sendRawTransaction(self: *EthereumRpc, signed_tx: []const u8) ![]const u8 {
        const result = try self.call("eth_sendRawTransaction", .{
            .array = &[_]std.json.Value{.{ .string = signed_tx }},
        });
        
        if (result != .string) {
            return RpcError.InvalidResponse;
        }
        
        // Return tx hash (transfers ownership to caller)
        return result.string;
    }
    
    /// Get transaction receipt
    pub fn getTransactionReceipt(self: *EthereumRpc, tx_hash: []const u8) !?TransactionReceipt {
        const result = try self.call("eth_getTransactionReceipt", .{
            .array = &[_]std.json.Value{.{ .string = tx_hash }},
        });
        defer freeJsonValue(self.allocator, result);
        
        if (result == .null) {
            return null; // Transaction pending
        }
        
        if (result != .object) {
            return RpcError.InvalidResponse;
        }
        
        return try parseTransactionReceipt(self.allocator, result.object);
    }
    
    /// Subscribe to new blocks (WebSocket)
    pub fn subscribeNewBlocks(self: *EthereumRpc, callback: fn (block: BlockHeader) void) !void {
        // TODO: Implement WebSocket subscription using TokioZ
        _ = self;
        _ = callback;
        return error.NotImplemented;
    }
};

// Helper structures
pub const TransactionRequest = struct {
    from: ?[]const u8 = null,
    to: ?[]const u8 = null,
    value: ?u256 = null,
    data: ?[]const u8 = null,
    gas: ?u64 = null,
    gas_price: ?u256 = null,
    nonce: ?u64 = null,
};

pub const TransactionReceipt = struct {
    transaction_hash: []const u8,
    block_hash: []const u8,
    block_number: u64,
    from: []const u8,
    to: ?[]const u8,
    gas_used: u64,
    status: bool,
    logs: []const Log,
    
    pub fn deinit(self: *TransactionReceipt, allocator: Allocator) void {
        allocator.free(self.transaction_hash);
        allocator.free(self.block_hash);
        allocator.free(self.from);
        if (self.to) |to| allocator.free(to);
        for (self.logs) |*log| {
            log.deinit(allocator);
        }
        allocator.free(self.logs);
    }
};

pub const Log = struct {
    address: []const u8,
    topics: []const []const u8,
    data: []const u8,
    
    pub fn deinit(self: *const Log, allocator: Allocator) void {
        allocator.free(self.address);
        for (self.topics) |topic| {
            allocator.free(topic);
        }
        allocator.free(self.topics);
        allocator.free(self.data);
    }
};

pub const BlockHeader = struct {
    number: u64,
    hash: []const u8,
    parent_hash: []const u8,
    timestamp: u64,
    miner: []const u8,
};

// Helper functions

fn parseRpcResponse(json: std.json.Value) !RpcResponse {
    if (json != .object) return RpcError.InvalidResponse;
    
    const obj = json.object;
    
    return RpcResponse{
        .jsonrpc = obj.get("jsonrpc").?.string,
        .result = obj.get("result"),
        .@"error" = if (obj.get("error")) |err| try parseRpcError(err) else null,
        .id = @intCast(obj.get("id").?.integer),
    };
}

fn parseRpcError(json: std.json.Value) !RpcErrorData {
    if (json != .object) return RpcError.InvalidResponse;
    
    const obj = json.object;
    
    return RpcErrorData{
        .code = @intCast(obj.get("code").?.integer),
        .message = obj.get("message").?.string,
        .data = obj.get("data"),
    };
}

fn parseTransactionReceipt(allocator: Allocator, obj: std.json.ObjectMap) !TransactionReceipt {
    const status_hex = obj.get("status").?.string;
    const status = if (std.mem.eql(u8, status_hex, "0x1")) true else false;
    
    var logs = std.ArrayList(Log).init(allocator);
    if (obj.get("logs")) |logs_json| {
        for (logs_json.array.items) |log_json| {
            try logs.append(try parseLog(allocator, log_json.object));
        }
    }
    
    return TransactionReceipt{
        .transaction_hash = try allocator.dupe(u8, obj.get("transactionHash").?.string),
        .block_hash = try allocator.dupe(u8, obj.get("blockHash").?.string),
        .block_number = try parseHexInt(u64, obj.get("blockNumber").?.string),
        .from = try allocator.dupe(u8, obj.get("from").?.string),
        .to = if (obj.get("to")) |to| try allocator.dupe(u8, to.string) else null,
        .gas_used = try parseHexInt(u64, obj.get("gasUsed").?.string),
        .status = status,
        .logs = try logs.toOwnedSlice(),
    };
}

fn parseLog(allocator: Allocator, obj: std.json.ObjectMap) !Log {
    var topics = std.ArrayList([]const u8).init(allocator);
    if (obj.get("topics")) |topics_json| {
        for (topics_json.array.items) |topic| {
            try topics.append(try allocator.dupe(u8, topic.string));
        }
    }
    
    return Log{
        .address = try allocator.dupe(u8, obj.get("address").?.string),
        .topics = try topics.toOwnedSlice(),
        .data = try allocator.dupe(u8, obj.get("data").?.string),
    };
}

fn cloneJsonValue(allocator: Allocator, value: std.json.Value) !std.json.Value {
    switch (value) {
        .null => return .null,
        .bool => |b| return .{ .bool = b },
        .integer => |i| return .{ .integer = i },
        .float => |f| return .{ .float = f },
        .string => |s| return .{ .string = try allocator.dupe(u8, s) },
        .array => |arr| {
            var new_arr = std.json.Array.init(allocator);
            for (arr.items) |item| {
                try new_arr.append(try cloneJsonValue(allocator, item));
            }
            return .{ .array = new_arr };
        },
        .object => |obj| {
            var new_obj = std.json.ObjectMap.init(allocator);
            var it = obj.iterator();
            while (it.next()) |entry| {
                const key = try allocator.dupe(u8, entry.key_ptr.*);
                try new_obj.put(key, try cloneJsonValue(allocator, entry.value_ptr.*));
            }
            return .{ .object = new_obj };
        },
    }
}

fn freeJsonValue(allocator: Allocator, value: std.json.Value) void {
    switch (value) {
        .string => |s| allocator.free(s),
        .array => |arr| {
            for (arr.items) |item| {
                freeJsonValue(allocator, item);
            }
            arr.deinit();
        },
        .object => |obj| {
            var it = obj.iterator();
            while (it.next()) |entry| {
                allocator.free(entry.key_ptr.*);
                freeJsonValue(allocator, entry.value_ptr.*);
            }
            obj.deinit();
        },
        else => {},
    }
}

fn parseHexInt(comptime T: type, hex: []const u8) !T {
    if (!std.mem.startsWith(u8, hex, "0x")) {
        return RpcError.InvalidResponse;
    }
    
    return try std.fmt.parseInt(T, hex[2..], 16);
}

fn calculateNamehash(allocator: Allocator, domain: []const u8) ![]u8 {
    var hash = try allocator.alloc(u8, 32);
    @memset(hash, 0);
    
    var labels = std.ArrayList([]const u8).init(allocator);
    defer labels.deinit();
    
    var iterator = std.mem.splitScalar(u8, domain, '.');
    while (iterator.next()) |label| {
        try labels.append(label);
    }
    
    var i = labels.items.len;
    while (i > 0) {
        i -= 1;
        const label = labels.items[i];
        
        if (label.len == 0) continue;
        
        var label_hash: [32]u8 = undefined;
        zcrypto.hash.keccak256.hash(label, &label_hash, .{});
        
        var combined = try allocator.alloc(u8, 64);
        defer allocator.free(combined);
        
        @memcpy(combined[0..32], hash);
        @memcpy(combined[32..64], &label_hash);
        
        zcrypto.hash.keccak256.hash(combined, hash[0..32], .{});
    }
    
    return hash;
}

/// RPC provider endpoints
pub const RpcProviders = struct {
    pub const INFURA_MAINNET = "https://mainnet.infura.io/v3/YOUR_PROJECT_ID";
    pub const ALCHEMY_MAINNET = "https://eth-mainnet.alchemyapi.io/v2/YOUR_API_KEY";
    pub const ANKR_MAINNET = "https://rpc.ankr.com/eth";
    pub const LLAMARPC_MAINNET = "https://eth.llamarpc.com";
    
    // Testnets
    pub const INFURA_SEPOLIA = "https://sepolia.infura.io/v3/YOUR_PROJECT_ID";
    pub const ALCHEMY_SEPOLIA = "https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY";
    
    // Local development
    pub const LOCALHOST = "http://127.0.0.1:8545";
    pub const HARDHAT = "http://127.0.0.1:8545";
    pub const ANVIL = "http://127.0.0.1:8545";
};

test "rpc client creation" {
    var rpc = try EthereumRpc.init(std.testing.allocator, RpcProviders.LOCALHOST);
    defer rpc.deinit();
    
    try std.testing.expect(std.mem.eql(u8, rpc.endpoint, RpcProviders.LOCALHOST));
}

test "hex parsing" {
    const hex = "0x1234567890abcdef";
    const value = try parseHexInt(u64, hex);
    try std.testing.expectEqual(@as(u64, 0x1234567890abcdef), value);
}