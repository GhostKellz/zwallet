# Zledger Documentation

## Overview

Zledger is a lightweight, embeddable ledger engine built in Zig designed for use in Web3 applications, cryptocurrency accounting, blockchain wallets, and local transactional systems. It provides precision-first double-entry accounting with no external dependencies.

## Integration with Zig Projects

### Adding Zledger as a Dependency

Add Zledger to your `build.zig.zon`:

```zig
.{
    .name = "your-project",
    .version = "0.1.0",
    .dependencies = .{
        .zledger = .{
            .url = "https://github.com/ghostkellz/zledger/archive/main.tar.gz",
            .hash = "12345...", // Use `zig fetch` to get the actual hash
        },
    },
}
```

### Build Configuration

In your `build.zig`, add the zledger module:

```zig
const zledger_dep = b.dependency("zledger", .{
    .target = target,
    .optimize = optimize,
});

const exe = b.addExecutable(.{
    .name = "your-app",
    .root_source_file = b.path("src/main.zig"),
    .target = target,
    .optimize = optimize,
});

exe.root_module.addImport("zledger", zledger_dep.module("zledger"));
```

### Basic Usage

```zig
const std = @import("std");
const zledger = @import("zledger");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Initialize ledger and journal
    var ledger = zledger.Ledger.init(allocator);
    defer ledger.deinit();
    
    var journal = zledger.Journal.init(allocator, "transactions.log");
    defer journal.deinit();

    // Create accounts
    try ledger.createAccount("wallet_1", .asset, "USD");
    try ledger.createAccount("wallet_2", .asset, "USD");

    // Create and process transaction
    var tx = try zledger.Transaction.init(
        allocator,
        100000, // Amount in micro-units (1000.00 USD)
        "USD",
        "wallet_1",
        "wallet_2",
        "Transfer between wallets"
    );
    defer tx.deinit(allocator);

    try ledger.processTransaction(tx);
    try journal.append(tx);

    // Verify integrity
    var auditor = zledger.Auditor.init(allocator);
    var report = try auditor.auditLedger(&ledger, &journal);
    defer report.deinit(allocator);
    
    std.log.info("Ledger valid: {}", .{report.isValid()});
}
```

## Core API Reference

### Transaction (`zledger.Transaction`)

```zig
// Create a new transaction
var tx = try Transaction.init(
    allocator,
    amount: i64,        // Amount in micro-units
    currency: []const u8,
    from_account: []const u8,
    to_account: []const u8,
    memo: ?[]const u8,
);

// Serialize to JSON
const json = try tx.toJson(allocator);

// Get transaction hash for integrity
const hash = try tx.getHash(allocator);
```

### Account Management (`zledger.Ledger`)

```zig
var ledger = Ledger.init(allocator);

// Create accounts
try ledger.createAccount("account_name", .asset, "USD");
// Account types: .asset, .liability, .equity, .revenue, .expense

// Process transactions (double-entry)
try ledger.processTransaction(transaction);

// Get balances
const balance = ledger.getBalance("account_name");

// Verify double-entry integrity
const is_balanced = ledger.verifyDoubleEntry();
```

### Journal & Persistence (`zledger.Journal`)

```zig
var journal = Journal.init(allocator, "ledger.log");

// Append transactions (creates integrity chain)
try journal.append(transaction);

// Load from file
try journal.loadFromFile("existing_ledger.log");

// Verify chain integrity
const is_valid = try journal.verifyIntegrity();

// Get transaction history
const tx_history = try journal.getTransactionsByAccount(allocator, "wallet_1");
```

### Auditing (`zledger.Auditor`)

```zig
var auditor = Auditor.init(allocator);
var report = try auditor.auditLedger(&ledger, &journal);

// Check overall validity
const is_valid = report.isValid();

// Detailed checks
std.log.info("Integrity: {}", .{report.integrity_valid});
std.log.info("Double-entry: {}", .{report.double_entry_valid});
std.log.info("Discrepancies: {}", .{report.balance_discrepancies.items.len});
```

### Fixed-Point Arithmetic (`zledger.FixedPoint`)

```zig
// Create from different sources
const fp1 = FixedPoint.fromFloat(123.456);
const fp2 = try FixedPoint.fromString(allocator, "78.90");
const fp3 = FixedPoint.fromInt(100);

// Arithmetic operations
const sum = fp1.add(fp2);
const product = fp1.mul(fp2);
const quotient = try fp1.div(fp2);

// Convert back
const as_float = sum.toFloat();
const as_string = try sum.toString(allocator);

// Convert between micro-units and FixedPoint
const amount_cents: i64 = 150000; // $1500.00
const fp = convertAmountToFixedPoint(amount_cents);
const back_to_cents = convertFixedPointToAmount(fp);
```

## Integration Examples

### For ZSig (Digital Signatures)

```zig
// Sign transaction hash
const tx_hash = try transaction.getHash(allocator);
const signature = try zsig.sign(private_key, &tx_hash);

// Verify transaction signature before processing
if (try zsig.verify(public_key, &tx_hash, signature)) {
    try ledger.processTransaction(transaction);
    try journal.append(transaction);
}
```

### For ZWallet (Wallet Management)

```zig
// Create wallet accounts
try ledger.createAccount(wallet.address, .asset, wallet.currency);

// Process wallet transactions
const tx = try Transaction.init(
    allocator,
    wallet.prepareAmount(amount),
    wallet.currency,
    wallet.address,
    recipient_address,
    "Wallet transfer"
);

try ledger.processTransaction(tx);
try journal.append(tx);

// Get wallet balance
const balance = ledger.getBalance(wallet.address);
wallet.updateBalance(balance);
```

### For ZCrypto (Cryptographic Operations)

```zig
// Enhanced transaction with crypto verification
const tx_data = try transaction.toJson(allocator);
const encrypted_memo = try zcrypto.encrypt(tx.memo, encryption_key);
const tx_signature = try zcrypto.sign(tx_data, signing_key);

// Store crypto metadata with transaction
// (extend Transaction struct as needed)
```

### For ZVM (Virtual Machine)

```zig
// VM account for smart contract execution
try ledger.createAccount("contract_0x123", .asset, "ETH");

// Execute contract transaction
const result = try zvm.execute(contract_bytecode, input_data);
if (result.success) {
    const tx = try Transaction.init(
        allocator,
        result.gas_cost,
        "ETH",
        "user_wallet",
        "contract_0x123",
        "Smart contract execution"
    );
    try ledger.processTransaction(tx);
}
```

### For CNS (QUIC-based DNS)

```zig
// DNS service accounting
try ledger.createAccount("cns_service", .revenue, "USD");
try ledger.createAccount("user_credits", .asset, "USD");

// Charge for DNS resolution
const dns_tx = try Transaction.init(
    allocator,
    dns_query_cost,
    "USD",
    "user_credits",
    "cns_service",
    "DNS resolution fee"
);

try ledger.processTransaction(dns_tx);
try journal.append(dns_tx);
```

## Configuration Options

### Precision Settings

```zig
// Default: 8 decimal places (100,000,000 scale factor)
// Modify in fixed_point.zig if different precision needed
pub const DECIMAL_PLACES: u8 = 8;
pub const SCALE_FACTOR: i64 = 100_000_000;
```

### Journal Settings

```zig
// Auto-persistence enabled by default
var journal = Journal.init(allocator, "path/to/ledger.log");

// In-memory only
var journal = Journal.init(allocator, null);
```

## Error Handling

Common error types to handle:

```zig
// Account errors
error.AccountExists
error.FromAccountNotFound
error.ToAccountNotFound

// Transaction errors
error.CurrencyMismatch
error.DivisionByZero

// File I/O errors
error.FileNotFound
error.AccessDenied

// Memory errors
error.OutOfMemory
```

## Performance Considerations

- **Memory**: All operations use provided allocator
- **File I/O**: Journal appends are atomic and efficient
- **Hashing**: SHA256 used for integrity (can be disabled if needed)
- **Precision**: Fixed-point arithmetic prevents floating-point errors
- **Concurrency**: Single-threaded design (use tokioZ for async)

## Testing

Run the test suite:

```bash
zig build test
```

Individual module tests are included in each source file.

## CLI Usage

The zledger CLI can be used for testing and development:

```bash
# Create accounts
zledger account create alice asset USD
zledger account create bob asset USD

# Add transactions
zledger tx add --from alice --to bob --amount 100000 --currency USD --memo "Payment"

# Check balances
zledger balance alice

# Audit ledger
zledger audit verify
```

## License

MIT - See LICENSE file for details.

## Contributing

This ledger engine is designed to be embedded in the Ghost ecosystem (zsig, zwallet, zcrypto, zvm, cns). For issues or feature requests, please file them in the appropriate project repository.