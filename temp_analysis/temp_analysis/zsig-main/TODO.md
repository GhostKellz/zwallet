# Zsig v0.3.0 TODO List

## 🎯 **Version 0.3.0 Goals**
Complete zcrypto v0.3.0 integration and prepare for full GhostChain ecosystem deployment.

---

## 🔥 **Critical Fixes (P0)**

### Backend System Issues
- [ ] **Fix std.crypto Backend**: Update std.crypto Ed25519 API calls
  - `std.crypto.sign.Ed25519.KeyPair.create()` → use correct API
  - Fix 64-byte vs 96-byte key length issues
  - Update signature verification API calls
  - **Files**: `src/zsig/backend.zig` lines 198, 208, 220, 229

### Test Suite Compatibility
- [ ] **Update Test Files**: Fix `.public` → `.publicKey()` references
  - **Files**: `src/zsig.zig`, `src/zsig/verify.zig`
  - Replace `keypair.public` with `keypair.publicKey()`
  - Update all test assertions to use new backend API
  - **Lines affected**: ~13 errors across test files

### API Consistency
- [ ] **Harmonize Key Field Names**: Ensure consistent naming
  - Backend uses `private_key` but some legacy code expects `secret_key`
  - Update any remaining `secret_key` references
  - **Files**: Check `src/zsig/key.zig` for any missed references

---

## 🚀 **Feature Enhancements (P1)**

### zcrypto v0.3.0 Advanced Features
- [ ] **Implement Batch Operations**: Leverage zcrypto's new batch signing
  ```zig
  pub fn signBatchZcrypto(messages: []const []const u8, keypair: Keypair, allocator: std.mem.Allocator) ![]Signature
  pub fn verifyBatchZcrypto(messages: []const []const u8, signatures: []const Signature, public_keys: []const [32]u8, allocator: std.mem.Allocator) ![]bool
  ```

- [ ] **Zero-Copy Operations**: Add in-place signing functions
  ```zig
  pub fn signInPlace(message: []const u8, keypair: Keypair, signature_buffer: *[64]u8) !void
  pub fn hashInPlace(message: []const u8, hash_buffer: *[32]u8) void
  ```

- [ ] **Enhanced Error Handling**: Use zcrypto's improved error types
  - Replace generic `anyerror` with specific error types
  - Add detailed error messages for debugging

### Multi-Algorithm Support
- [ ] **Add secp256k1 Support**: Bitcoin/Ethereum compatibility
  ```zig
  pub const Algorithm = enum { ed25519, secp256k1, secp256r1 };
  pub const MultiAlgKeypair = union(Algorithm) { ... };
  ```

- [ ] **Add secp256r1 Support**: NIST P-256 curve support
- [ ] **Unified Multi-Sig API**: Cross-algorithm signing interface

---

## 🔧 **Integration & CLI Improvements (P2)**

### CLI Enhancements
- [ ] **Add Multi-Algorithm CLI Support**:
  ```bash
  zsig keygen --algorithm secp256k1 --out bitcoin_key
  zsig sign --algorithm ed25519 --in message.txt --key ed25519.key
  zsig verify --algorithm secp256k1 --in tx_hash --sig sig --pubkey pubkey
  ```

- [ ] **Add Batch Operations CLI**:
  ```bash
  zsig batch-sign --in messages/ --key batch.key --out signatures/
  zsig batch-verify --messages messages/ --signatures signatures/ --pubkey batch.pub
  ```

- [ ] **Add Performance Benchmarks**:
  ```bash
  zsig benchmark --algorithm ed25519 --iterations 10000
  zsig benchmark --batch-size 1000 --algorithm secp256k1
  ```

### Hardware Wallet Integration Prep
- [ ] **Add Hardware Wallet Interface**: Prepare for YubiKey/TPM integration
  ```zig
  pub const HardwareWallet = struct {
      pub fn sign(device_path: []const u8, message: []const u8) !Signature;
      pub fn getPublicKey(device_path: []const u8) ![32]u8;
  };
  ```

---

## 📚 **Documentation & Examples (P2)**

### Integration Examples
- [ ] **Create zwallet Integration Example**: 
  - File: `examples/zwallet_integration.zig`
  - Show Bitcoin transaction signing with secp256k1
  - Demonstrate HD wallet key derivation

- [ ] **Create zledger Integration Example**:
  - File: `examples/zledger_integration.zig`  
  - Show transaction verification workflows
  - Demonstrate batch verification for performance

- [ ] **Create CNS Integration Example**:
  - File: `examples/cns_integration.zig`
  - Show DNS signing and validation
  - Demonstrate domain separation contexts

### API Documentation
- [ ] **Update README.md**: Add zcrypto v0.3.0 features
- [ ] **Create API Reference**: Generate docs for all public functions
- [ ] **Add Performance Guide**: Benchmark results and optimization tips

---

## 🔬 **Testing & Quality (P2)**

### Test Coverage
- [ ] **Add Integration Tests**: Full workflow testing
  ```zig
  test "zwallet integration workflow" { ... }
  test "zledger batch verification" { ... }
  test "cns domain signing" { ... }
  ```

- [ ] **Add Performance Tests**: Benchmark critical paths
- [ ] **Add Compatibility Tests**: Cross-algorithm verification
- [ ] **Add Fuzzing Tests**: Input validation and edge cases

### CI/CD Improvements
- [ ] **Add Multi-Platform Testing**: Linux, macOS, Windows
- [ ] **Add WASM Build Tests**: Ensure WASM compatibility
- [ ] **Add Memory Leak Detection**: Valgrind integration
- [ ] **Add Security Scanning**: Static analysis integration

---

## 🌟 **Future Roadmap (P3)**

### Advanced Cryptography
- [ ] **Post-Quantum Preparation**: Research integration paths
- [ ] **Zero-Knowledge Proof Support**: zk-SNARK/STARK integration
- [ ] **Threshold Signatures**: Multi-party signing schemes
- [ ] **Ring Signatures**: Privacy-preserving signatures

### Performance Optimizations
- [ ] **SIMD Optimizations**: Leverage CPU vector instructions
- [ ] **GPU Acceleration**: CUDA/OpenCL for batch operations
- [ ] **Memory Pool Management**: Reduce allocation overhead
- [ ] **Assembly Optimizations**: Critical path assembly code

### Ecosystem Integration
- [ ] **WebAssembly Module**: Browser-compatible signing
- [ ] **Mobile SDKs**: iOS/Android integration
- [ ] **Language Bindings**: Python, Rust, Go, JavaScript FFI
- [ ] **Docker Containers**: Production deployment images

---

## 📋 **Current Status Summary**

### ✅ **Completed**
- ✅ zcrypto v0.3.0 dependency integration
- ✅ Basic Ed25519 functionality working
- ✅ CLI executable builds and runs
- ✅ Key generation and basic signing operational
- ✅ Pluggable backend system architecture

### 🔄 **In Progress**
- 🔄 Test suite compatibility updates
- 🔄 std.crypto backend API fixes
- 🔄 Error handling improvements

### ⏸️ **Blocked/Waiting**
- ⏸️ Full zcrypto v0.3.0 feature exploration (depends on test fixes)
- ⏸️ Multi-algorithm implementation (depends on core stability)
- ⏸️ Hardware wallet integration (depends on API finalization)

---

## 🎯 **Immediate Next Steps (This Sprint)**

1. **Fix Test Suite** (2-3 hours)
   - Update all `.public` → `.publicKey()` references
   - Fix std.crypto backend API calls
   - Ensure all tests pass

2. **Implement Batch Operations** (4-6 hours)
   - Add zcrypto batch signing/verification
   - Update CLI with batch commands
   - Add performance benchmarks

3. **Add secp256k1 Support** (6-8 hours)
   - Implement Bitcoin-compatible signing
   - Add multi-algorithm CLI interface
   - Create zwallet integration example

4. **Documentation Update** (2-3 hours)
   - Update README with new features
   - Add integration examples
   - Document performance improvements

---

## 💡 **Notes & Considerations**

### Technical Debt
- Consider refactoring backend interface to be more type-safe
- Evaluate memory management patterns for large-scale deployments
- Review error handling strategies for production use

### Security Considerations
- Audit all cryptographic operations for side-channel resistance
- Implement secure memory clearing for sensitive data
- Add input validation for all public APIs

### Performance Targets
- **Ed25519 Signing**: Target <1ms per operation
- **Batch Operations**: Target >10k operations/second
- **Memory Usage**: Keep <1MB for embedded deployments
- **Binary Size**: Target <500KB for minimal builds

---

**Last Updated**: June 26, 2025  
**Version**: 0.3.0-dev  
**Priority**: High (GhostChain ecosystem dependency)
