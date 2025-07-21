# ZWallet v0.3.1 TODO List

## Priority 1: Critical Bug Fixes & Core Functionality

### 1. Fix Version Inconsistency
- **Issue**: `src/root.zig:47` shows version "0.1.0" but `build.zig.zon:3` shows "0.3.1"
- **Action**: Update version string in `src/root.zig` to match current release
- **Files**: `src/root.zig`

### 2. Complete Crypto Integration (HIGH PRIORITY)
- **Issue**: Multiple TODOs indicate incomplete zcrypto v0.3.0 integration
- **Actions**:
  - Implement BIP-32 key derivation in `src/utils/crypto.zig:240`
  - Replace placeholder BIP-39 implementation with zcrypto v0.3.0 in `src/utils/crypto.zig:288,297`
  - Update keystore encryption to use zcrypto AES-256-CTR in `src/utils/keystore.zig:230,245,257`
- **Files**: `src/utils/crypto.zig`, `src/utils/keystore.zig` 

### 3. Implement Transaction Signing
- **Issue**: Core transaction signing uses placeholder implementation
- **Actions**:
  - Replace placeholder signing with zsig integration in `src/protocol/transaction.zig:63`
  - Complete GhostChain RPC implementation in `src/protocol/transaction.zig:86`
  - Add Ethereum RPC calls in `src/protocol/transaction.zig:106`
- **Files**: `src/protocol/transaction.zig`

## Priority 2: Protocol Support & Network Integration

### 4. Complete Network Protocol Implementations
- **Issue**: Multiple protocol clients are stubbed out
- **Actions**:
  - Implement GhostChain RPC client in `src/protocol/network.zig:165`
  - Add Stellar Horizon client in `src/protocol/network.zig:169`
  - Complete Hedera client in `src/protocol/network.zig:173`
  - Add Ripple client in `src/protocol/network.zig:177`
- **Files**: `src/protocol/network.zig`, `src/protocol/ethereum_rpc.zig`

### 5. Enhance GhostChain Integration
- **Issue**: GhostChain integration has multiple unimplemented features
- **Actions**:
  - Implement HTTP/HTTPS client for ghostd communication in `src/protocol/ghostd_integration.zig:271`
  - Add transaction anonymization in `src/protocol/ghostd_integration.zig:330`
  - Complete ZK proof generation in `src/protocol/ghostd_integration.zig:337`
  - Implement mixnet routing setup in `src/protocol/ghostd_integration.zig:344`
- **Files**: `src/protocol/ghostd_integration.zig`

## Priority 3: User Experience & Interface

### 6. Complete CLI Command Implementation
- **Issue**: New v0.3.0 commands are marked as TODO
- **Actions**:
  - Implement new CLI commands in `src/cli/commands.zig:81`
  - Add secure password prompting in `src/cli/commands.zig:326`
  - Complete balance lookup by address in `src/cli/commands.zig:219`
- **Files**: `src/cli/commands.zig`

### 7. Improve Web3 Bridge API
- **Issue**: Multiple bridge API methods are unimplemented
- **Actions**:
  - Add user permission prompts in `src/bridge/api.zig:155`
  - Implement transaction parameter parsing in `src/bridge/api.zig:180,181`
  - Complete message signing with user approval in `src/bridge/api.zig:194`
  - Add chain management in `src/bridge/api.zig:204,213`
- **Files**: `src/bridge/api.zig`

## Priority 4: Security & Identity Features

### 8. Complete Identity Resolution System
- **Issue**: Multiple identity providers are not implemented
- **Actions**:
  - Implement Unstoppable Domains resolution in `src/identity/resolver.zig:108`
  - Add DNS TXT record resolution in `src/identity/resolver.zig:123`
  - Complete Handshake blockchain resolution in `src/identity/resolver.zig:134`
  - Add reverse resolution for ENS/Unstoppable in `src/identity/resolver.zig:227`
- **Files**: `src/identity/resolver.zig`

### 9. Enhance Wallet Security Features
- **Issue**: Several wallet security features are incomplete
- **Actions**:
  - Implement BIP-39 mnemonic to seed derivation in `src/core/wallet.zig:125`
  - Complete keystore encryption/decryption in `src/core/wallet.zig:191,200,207`
  - Fix address generation to use proper Keccak256 in `src/core/wallet.zig:225`
- **Files**: `src/core/wallet.zig`, `src/core/wallet_realid.zig`

## Priority 5: Build System & Dependencies

### 10. Clean Up Build Configuration
- **Issue**: Build system has disabled components and needs cleanup
- **Actions**:
  - Re-enable RealID CLI example (lines 123-144 in `build.zig`)
  - Re-enable FFI library build (lines 146-166 in `build.zig`)
  - Review and update dependency versions in `build.zig.zon`
- **Files**: `build.zig`, `build.zig.zon`

## Additional Improvements for v0.3.1

### Code Quality & Testing
- Add comprehensive test coverage for all core modules
- Implement proper error handling throughout the codebase
- Add input validation and sanitization
- Create integration tests for protocol implementations

### Documentation
- Update README.md with current feature status
- Add comprehensive API documentation
- Create usage examples for all major features
- Document build and deployment procedures

### Performance Optimizations
- Profile and optimize cryptographic operations
- Implement connection pooling for RPC clients
- Add caching for frequently accessed data
- Optimize memory usage in core modules

---

## Development Notes

**Dependencies Status:**
- zcrypto: v0.8.4 (main branch)
- zsync: v0.3.2 (async runtime, lazy loaded)
- realid: Not in build.zig.zon (commented out in build.zig)
- zsig: Not in build.zig.zon (commented out in build.zig)

**Architecture Notes:**
- Core wallet functionality split between `wallet.zig` and `wallet_realid.zig`
- Bridge API provides Web3 compatibility layer
- Protocol implementations are modular and extensible
- Identity resolution supports multiple providers

**Testing Priority:**
1. Core wallet operations (create, import, sign)
2. Cryptographic functions (BIP-39, BIP-32, signing)
3. Network protocol integrations
4. Bridge API endpoints
5. CLI command functionality
