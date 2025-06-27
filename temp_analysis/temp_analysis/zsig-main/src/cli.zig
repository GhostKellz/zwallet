//! Command-line interface for Zsig cryptographic operations
//! Provides keygen, sign, verify, and key management commands

const std = @import("std");
const zsig = @import("zsig.zig");
const fs = std.fs;
const print = std.debug.print;

const CliError = error{
    InvalidArguments,
    FileNotFound,
    InvalidKeyFormat,
    InvalidSignatureFormat,
    VerificationFailed,
    KeyGenerationFailed,
    FileWriteError,
    FileReadError,
};

const Command = enum {
    keygen,
    sign,
    verify,
    pubkey,
    help,
    version,
};

const Args = struct {
    command: Command,
    input_file: ?[]const u8 = null,
    output_file: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
    signature_file: ?[]const u8 = null,
    public_key_file: ?[]const u8 = null,
    seed: ?[]const u8 = null,
    passphrase: ?[]const u8 = null,
    context: ?[]const u8 = null,
    format: []const u8 = "base64", // base64, hex, raw
    inline_mode: bool = false,
    verbose: bool = false,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = std.process.argsAlloc(allocator) catch |err| {
        print("Error: Failed to parse arguments: {}\n", .{err});
        return;
    };
    defer std.process.argsFree(allocator, args);

    const parsed_args = parseArgs(args) catch |err| {
        switch (err) {
            CliError.InvalidArguments => {
                print("Error: Invalid arguments. Use 'zsig help' for usage information.\n", .{});
                return;
            },
            else => {
                print("Error: Failed to parse arguments: {}\n", .{err});
                return;
            },
        }
    };

    switch (parsed_args.command) {
        .keygen => try cmdKeygen(allocator, parsed_args),
        .sign => try cmdSign(allocator, parsed_args),
        .verify => try cmdVerify(allocator, parsed_args),
        .pubkey => try cmdPubkey(allocator, parsed_args),
        .help => cmdHelp(),
        .version => cmdVersion(),
    }
}

fn parseArgs(args: [][:0]u8) !Args {
    if (args.len < 2) return CliError.InvalidArguments;

    const command_str = args[1];
    const command = std.meta.stringToEnum(Command, command_str) orelse return CliError.InvalidArguments;

    var parsed = Args{ .command = command };
    
    var i: usize = 2;
    while (i < args.len) : (i += 2) {
        if (i + 1 >= args.len) break;
        
        const flag = args[i];
        const value = args[i + 1];
        
        if (std.mem.eql(u8, flag, "--in") or std.mem.eql(u8, flag, "-i")) {
            parsed.input_file = value;
        } else if (std.mem.eql(u8, flag, "--out") or std.mem.eql(u8, flag, "-o")) {
            parsed.output_file = value;
        } else if (std.mem.eql(u8, flag, "--key") or std.mem.eql(u8, flag, "-k")) {
            parsed.key_file = value;
        } else if (std.mem.eql(u8, flag, "--sig") or std.mem.eql(u8, flag, "-s")) {
            parsed.signature_file = value;
        } else if (std.mem.eql(u8, flag, "--pubkey") or std.mem.eql(u8, flag, "-p")) {
            parsed.public_key_file = value;
        } else if (std.mem.eql(u8, flag, "--seed")) {
            parsed.seed = value;
        } else if (std.mem.eql(u8, flag, "--passphrase")) {
            parsed.passphrase = value;
        } else if (std.mem.eql(u8, flag, "--context")) {
            parsed.context = value;
        } else if (std.mem.eql(u8, flag, "--format")) {
            parsed.format = value;
        } else if (std.mem.eql(u8, flag, "--inline")) {
            parsed.inline_mode = true;
            i -= 1; // No value for this flag
        } else if (std.mem.eql(u8, flag, "--verbose")) {
            parsed.verbose = true;
            i -= 1; // No value for this flag
        }
    }

    return parsed;
}

fn cmdKeygen(allocator: std.mem.Allocator, args: Args) !void {
    if (args.verbose) print("Generating Ed25519 keypair...\n", .{});

    const keypair = if (args.seed) |seed_str|
        blk: {
            if (seed_str.len != zsig.SEED_SIZE * 2) {
                print("Error: Seed must be exactly {} hex characters\n", .{zsig.SEED_SIZE * 2});
                return CliError.InvalidArguments;
            }
            var seed: [zsig.SEED_SIZE]u8 = undefined;
            _ = std.fmt.hexToBytes(&seed, seed_str) catch {
                print("Error: Invalid hex seed\n", .{});
                return CliError.InvalidArguments;
            };
            break :blk zsig.keypairFromSeed(seed);
        }
    else if (args.passphrase) |passphrase|
        try zsig.keypairFromPassphrase(allocator, passphrase, null)
    else
        try zsig.generateKeypair(allocator);

    // Generate output files
    const base_name = args.output_file orelse "zsig_key";
    
    // Write private key file (.key)
    const key_filename = try std.fmt.allocPrint(allocator, "{s}.key", .{base_name});
    defer allocator.free(key_filename);
    
    const key_bundle = try keypair.exportBundle(allocator);
    defer allocator.free(key_bundle);
    
    try writeFile(key_filename, key_bundle);
    
    // Write public key file (.pub)
    const pub_filename = try std.fmt.allocPrint(allocator, "{s}.pub", .{base_name});
    defer allocator.free(pub_filename);
    
    const pub_hex = try keypair.publicKeyHex(allocator);
    defer allocator.free(pub_hex);
    
    try writeFile(pub_filename, pub_hex);
    
    if (args.verbose) {
        print("Generated keypair:\n", .{});
        print("  Private key: {s}\n", .{key_filename});
        print("  Public key: {s}\n", .{pub_filename});
        print("  Public key (hex): {s}\n", .{pub_hex});
    } else {
        print("Keypair generated: {s}.key, {s}.pub\n", .{ base_name, base_name });
    }
}

fn cmdSign(allocator: std.mem.Allocator, args: Args) !void {
    const input_file = args.input_file orelse {
        print("Error: Input file required (--in)\n", .{});
        return CliError.InvalidArguments;
    };
    
    const key_file = args.key_file orelse {
        print("Error: Key file required (--key)\n", .{});
        return CliError.InvalidArguments;
    };

    if (args.verbose) print("Reading message from {s}...\n", .{input_file});
    const message = readFile(allocator, input_file) catch |err| {
        print("Error reading input file: {}\n", .{err});
        return CliError.FileReadError;
    };
    defer allocator.free(message);

    if (args.verbose) print("Loading keypair from {s}...\n", .{key_file});
    const keypair = try loadKeypair(allocator, key_file);

    if (args.verbose) print("Signing message...\n", .{});
    const signature = if (args.context) |context|
        try zsig.signWithContext(message, context, keypair)
    else
        try zsig.signMessage(message, keypair);

    // Output signature
    if (args.inline_mode) {
        const inline_sig = try zsig.signInline(allocator, message, keypair);
        defer allocator.free(inline_sig);
        
        const output_file = args.output_file orelse "signed_message";
        try writeFile(output_file, inline_sig);
        
        if (args.verbose) {
            print("Inline signature written to {s}\n", .{output_file});
        } else {
            print("Signed: {s}\n", .{output_file});
        }
    } else {
        const sig_data = if (std.mem.eql(u8, args.format, "hex"))
            try signature.toHex(allocator)
        else if (std.mem.eql(u8, args.format, "base64"))
            try signature.toBase64(allocator)
        else if (std.mem.eql(u8, args.format, "raw"))
            try allocator.dupe(u8, &signature.bytes)
        else {
            print("Error: Invalid format. Use hex, base64, or raw\n", .{});
            return CliError.InvalidArguments;
        };
        defer allocator.free(sig_data);

        const output_file = args.output_file orelse 
            try std.fmt.allocPrint(allocator, "{s}.sig", .{input_file});
        defer if (args.output_file == null) allocator.free(output_file);
        
        try writeFile(output_file, sig_data);
        
        if (args.verbose) {
            print("Signature ({s}) written to {s}\n", .{ args.format, output_file });
        } else {
            print("Signed: {s}\n", .{output_file});
        }
    }
}

fn cmdVerify(allocator: std.mem.Allocator, args: Args) !void {
    if (args.inline_mode) {
        const input_file = args.input_file orelse {
            print("Error: Input file required (--in)\n", .{});
            return CliError.InvalidArguments;
        };
        
        const public_key_file = args.public_key_file orelse {
            print("Error: Public key file required (--pubkey)\n", .{});
            return CliError.InvalidArguments;
        };

        const signed_message = try readFile(allocator, input_file);
        defer allocator.free(signed_message);
        
        const public_key = try loadPublicKey(allocator, public_key_file);
        
        const is_valid = zsig.verifyInline(signed_message, &public_key);
        
        if (is_valid) {
            print("✓ Signature valid\n", .{});
            if (args.verbose) {
                const extracted = zsig.verify.extractMessage(signed_message);
                print("Message: {s}\n", .{extracted});
            }
        } else {
            print("✗ Signature invalid\n", .{});
            return CliError.VerificationFailed;
        }
    } else {
        const input_file = args.input_file orelse {
            print("Error: Input file required (--in)\n", .{});
            return CliError.InvalidArguments;
        };
        
        const signature_file = args.signature_file orelse {
            print("Error: Signature file required (--sig)\n", .{});
            return CliError.InvalidArguments;
        };
        
        const public_key_file = args.public_key_file orelse {
            print("Error: Public key file required (--pubkey)\n", .{});
            return CliError.InvalidArguments;
        };

        const message = try readFile(allocator, input_file);
        defer allocator.free(message);
        
        const signature_data = try readFile(allocator, signature_file);
        defer allocator.free(signature_data);
        
        const public_key = try loadPublicKey(allocator, public_key_file);

        const is_valid = if (args.context) |context|
            zsig.verifyWithContext(message, context, signature_data, &public_key)
        else
            zsig.verifySignature(message, signature_data, &public_key);

        if (is_valid) {
            print("✓ Signature valid\n", .{});
        } else {
            print("✗ Signature invalid\n", .{});
            return CliError.VerificationFailed;
        }
    }
}

fn cmdPubkey(allocator: std.mem.Allocator, args: Args) !void {
    const key_file = args.key_file orelse {
        print("Error: Key file required (--key)\n", .{});
        return CliError.InvalidArguments;
    };

    const keypair = try loadKeypair(allocator, key_file);
    const pub_hex = try keypair.publicKeyHex(allocator);
    defer allocator.free(pub_hex);

    if (args.output_file) |output| {
        try writeFile(output, pub_hex);
        print("Public key written to {s}\n", .{output});
    } else {
        print("{s}\n", .{pub_hex});
    }
}

fn cmdHelp() void {
    print(
        \\Zsig v{s} - Cryptographic Signing Engine for Zig
        \\
        \\USAGE:
        \\    zsig <COMMAND> [OPTIONS]
        \\
        \\COMMANDS:
        \\    keygen      Generate a new Ed25519 keypair
        \\    sign        Sign a message or file
        \\    verify      Verify a signature
        \\    pubkey      Extract public key from private key file
        \\    help        Show this help message
        \\    version     Show version information
        \\
        \\KEYGEN OPTIONS:
        \\    --out <file>        Output filename prefix (default: zsig_key)
        \\    --seed <hex>        Use specific 64-char hex seed (deterministic)
        \\    --passphrase <str>  Generate from passphrase (deterministic)
        \\
        \\SIGN OPTIONS:
        \\    --in <file>         Input file to sign
        \\    --key <file>        Private key file (.key)
        \\    --out <file>        Output signature file (default: input.sig)
        \\    --context <str>     Additional context for domain separation
        \\    --format <fmt>      Output format: base64, hex, raw (default: base64)
        \\    --inline            Create inline signature (message + signature)
        \\
        \\VERIFY OPTIONS:
        \\    --in <file>         Input file (message or inline signature)
        \\    --sig <file>        Signature file (not needed with --inline)
        \\    --pubkey <file>     Public key file (.pub)
        \\    --context <str>     Context used during signing
        \\    --inline            Verify inline signature
        \\
        \\EXAMPLES:
        \\    zsig keygen --out alice
        \\    zsig sign --in message.txt --key alice.key
        \\    zsig verify --in message.txt --sig message.txt.sig --pubkey alice.pub
        \\    zsig sign --in tx.json --key alice.key --context "transaction-v1"
        \\
    , .{zsig.version});
}

fn cmdVersion() void {
    print("Zsig v{s}\n", .{zsig.version});
    print("Ed25519 cryptographic signing engine for Zig\n", .{});
    print("Author: {s}\n", .{zsig.info.author});
    print("License: {s}\n", .{zsig.info.license});
}

// Utility functions

fn readFile(allocator: std.mem.Allocator, filename: []const u8) ![]u8 {
    const file = fs.cwd().openFile(filename, .{}) catch return CliError.FileNotFound;
    defer file.close();
    
    const file_size = try file.getEndPos();
    const contents = try allocator.alloc(u8, file_size);
    _ = try file.readAll(contents);
    
    return contents;
}

fn writeFile(filename: []const u8, data: []const u8) !void {
    const file = fs.cwd().createFile(filename, .{}) catch return CliError.FileWriteError;
    defer file.close();
    
    try file.writeAll(data);
}

fn loadKeypair(allocator: std.mem.Allocator, filename: []const u8) !zsig.Keypair {
    const contents = try readFile(allocator, filename);
    defer allocator.free(contents);
    
    // Parse the key bundle format
    const private_start = "Private: ";
    const private_start_idx = std.mem.indexOf(u8, contents, private_start) orelse
        return CliError.InvalidKeyFormat;
    
    const private_data_start = private_start_idx + private_start.len;
    const private_end_idx = std.mem.indexOf(u8, contents[private_data_start..], "\n") orelse
        return CliError.InvalidKeyFormat;
    
    const private_b64 = contents[private_data_start..private_data_start + private_end_idx];
    
    return zsig.Keypair.fromPrivateKeyBase64(private_b64) catch CliError.InvalidKeyFormat;
}

fn loadPublicKey(allocator: std.mem.Allocator, filename: []const u8) ![zsig.PUBLIC_KEY_SIZE]u8 {
    const contents = try readFile(allocator, filename);
    defer allocator.free(contents);
    
    // Remove newlines and whitespace
    var clean_hex = std.ArrayList(u8).init(allocator);
    defer clean_hex.deinit();
    
    for (contents) |char| {
        if (std.ascii.isAlphanumeric(char)) {
            try clean_hex.append(char);
        }
    }
    
    return zsig.Keypair.publicKeyFromHex(clean_hex.items) catch CliError.InvalidKeyFormat;
}
