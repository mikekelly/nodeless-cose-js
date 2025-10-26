# nodeless-cose-js

**Runtime-agnostic JavaScript implementation of [COSE](https://tools.ietf.org/html/rfc9053) (CBOR Object Signing and Encryption)**

A fork of [`cose-js`](https://github.com/erdtman/cose-js) designed to work seamlessly across multiple JavaScript runtimes:
- ✅ **Node.js** - Full native support
- ✅ **React Native** - Babel-transpiled, no Node.js dependencies
- ✅ **Web Browsers** - Pure JavaScript, Web Crypto API compatible

## Features

- 🔒 **Secure** - Uses [`@noble/curves`](https://github.com/paulmillr/noble-curves) (audited, actively maintained)
- 🌐 **Cross-platform** - No Node.js-specific dependencies
- 🎯 **Modern** - ES6+, async/await, low-S signatures (RFC 6979 + BIP 62)
- ✅ **Tested** - 29 tests passing in Node.js, 16 in React Native/Babel
- 🔄 **Interoperable** - Compatible with other COSE implementations

## Current Status: Phase 1 - Sign1 Operations

Phase 1 focuses exclusively on **Sign1** (single-signer) messages:
- ✅ Create Sign1 messages
- ✅ Verify Sign1 messages
- ✅ ES256, ES384, ES512 algorithms
- ✅ External AAD support
- ✅ Protected and unprotected headers

**Future phases** will add Mac, Mac0, Encrypt, Encrypt0, and multi-signature support.

## Install

```bash
npm install nodeless-cose-js --save
```

## Usage

### Create and Sign a Message (Sign1)

```javascript
const cose = require('nodeless-cose-js');
const { p256 } = require('@noble/curves/nist.js');

// Generate a new private key (or load from storage)
const privateKey = p256.utils.randomPrivateKey();  // 32 bytes
// OR from hex: const privateKey = Buffer.from('your-private-key-hex', 'hex');

// Your message to sign
const plaintext = 'Important message!';

// Headers (protected and/or unprotected)
const headers = {
  p: { alg: 'ES256' },  // Protected: algorithm
  u: { kid: '11' }       // Unprotected: key ID
};

// Signer with private key
const signer = {
  key: privateKey  // Uint8Array or Buffer (32 bytes for ES256)
};

// Create signed message
const signedMessage = await cose.sign.create(headers, plaintext, signer);

console.log('COSE Sign1 message:', signedMessage.toString('hex'));
```

### Verify a Signed Message

```javascript
const cose = require('nodeless-cose-js');
const { p256 } = require('@noble/curves/nist.js');

// COSE Sign1 message (received from somewhere)
const signedMessage = Buffer.from('d28443a10126a10442313172496d706f7274616e74206d657373616765215840...', 'hex');

// Get the public key (derived from private key, or received from sender)
const privateKey = Buffer.from('6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19', 'hex');
const publicKey = p256.getPublicKey(privateKey);  // 33 bytes (compressed) or 65 bytes (uncompressed)

// Verifier with public key
const verifier = {
  key: publicKey  // Uint8Array or Buffer
};

// Verify and extract payload
const payload = await cose.sign.verify(signedMessage, verifier);

console.log('Verified message:', payload.toString('utf8'));
// Output: Important message!
```

### Sign with External AAD (Additional Authenticated Data)

```javascript
const cose = require('nodeless-cose-js');
const { p256 } = require('@noble/curves/nist.js');

const privateKey = p256.utils.randomPrivateKey();
const plaintext = 'Secret data';
const headers = {
  p: { alg: 'ES256' },
  u: { kid: 'key-1' }
};

const signer = {
  key: privateKey,
  externalAAD: Buffer.from('context-specific-data', 'utf8')  // External AAD
};

const signedMessage = await cose.sign.create(headers, plaintext, signer);
```

### Verify with External AAD

```javascript
const publicKey = p256.getPublicKey(privateKey);

const verifier = {
  key: publicKey,
  externalAAD: Buffer.from('context-specific-data', 'utf8')  // Must match!
};

const payload = await cose.sign.verify(signedMessage, verifier);
```

### Working with Only Unprotected Headers

```javascript
// No protected headers
const headers = {
  u: { 
    alg: 'ES256',
    kid: 'my-key-id'
  }
};

const signedMessage = await cose.sign.create(headers, plaintext, signer);
```

### ES384 and ES512 Algorithms

```javascript
const { p384, p521 } = require('@noble/curves/nist.js');

// ES384 (P-384 curve, SHA-384)
const privateKey384 = p384.utils.randomPrivateKey();  // 48 bytes
const publicKey384 = p384.getPublicKey(privateKey384);

const headers384 = { p: { alg: 'ES384' } };
const signer384 = { key: privateKey384 };

// ES512 (P-521 curve, SHA-512)  
const privateKey512 = p521.utils.randomPrivateKey();  // 66 bytes
const publicKey512 = p521.getPublicKey(privateKey512);

const headers512 = { p: { alg: 'ES512' } };
const signer512 = { key: privateKey512 };
```

## API Reference

### `cose.sign.create(headers, payload, signer, [options])`

Creates a signed COSE Sign1 message.

**Parameters:**
- `headers` (Object):
  - `p` (Object, optional): Protected headers (e.g., `{ alg: 'ES256' }`)
  - `u` (Object, optional): Unprotected headers (e.g., `{ kid: '11' }`)
- `payload` (Buffer|String): The message to sign
- `signer` (Object):
  - `key` (Uint8Array|Buffer): Private key (32 bytes for ES256, 48 for ES384, 66 for ES512)
  - `externalAAD` (Buffer, optional): External additional authenticated data
- `options` (Object, optional):
  - `excludetag` (Boolean): If true, omits the CBOR tag (default: false)

**Returns:** Promise<Buffer> - The COSE Sign1 message

### `cose.sign.verify(message, verifier, [options])`

Verifies a COSE Sign1 message and returns the payload.

**Parameters:**
- `message` (Buffer): The COSE Sign1 message to verify
- `verifier` (Object):
  - `key` (Uint8Array|Buffer): Public key in compressed (33/49/67 bytes) or uncompressed (65/97/133 bytes) format
  - `externalAAD` (Buffer, optional): External AAD (must match signing)
- `options` (Object, optional):
  - `defaultType` (Number): Default CBOR tag type if untagged

**Returns:** Promise<Buffer> - The verified payload

**Throws:** Error if signature is invalid

## Security Features

### Low-S Signatures (BIP 62)

This implementation uses **low-S normalization** for ECDSA signatures, following modern cryptographic best practices:

- **What it is**: For each signature `(r, s)`, we ensure `s < n/2` where `n` is the curve order
- **Why it matters**: Prevents signature malleability attacks
- **Compatibility**: Used by Bitcoin (BIP 62), Ethereum, and modern Web3 standards
- **COSE compliant**: RFC 9053 doesn't mandate low-S or high-S - both are valid

### RFC 6979 Deterministic ECDSA

All signatures are deterministic (same message + key = same signature), eliminating nonce-related vulnerabilities.

## Testing

### Node.js Tests
```bash
npm test
# 29 tests passed (Sign1 + interop)
```

### React Native / Babel Tests
```bash
npm run test:babel  
# 16 tests passed (Sign1 only)
```

### Interoperability Tests

Included tests verify compatibility with the `elliptic` library (used by original `cose-js`):
- ✅ Our signatures verify with elliptic
- ✅ We use RFC 6979 deterministic k generation
- ✅ We apply low-S normalization (security improvement)

## Supported Algorithms (Phase 1)

| Algorithm | Curve | Hash | Key Size | Status |
|-----------|-------|------|----------|--------|
| ES256 | P-256 | SHA-256 | 32 bytes | ✅ Supported |
| ES384 | P-384 | SHA-384 | 48 bytes | ✅ Supported |
| ES512 | P-521 | SHA-512 | 66 bytes | ✅ Supported |

**Note**: RSA algorithms (RS256, PS256, etc.) are not supported in Phase 1.

## Dependencies

### Runtime Dependencies
- [`@noble/curves`](https://github.com/paulmillr/noble-curves) - Modern, audited elliptic curve cryptography
- [`@noble/hashes`](https://github.com/paulmillr/noble-hashes) - Fast, secure hash functions
- [`cbor-x`](https://github.com/kriszyp/cbor-x) - High-performance CBOR encoding/decoding

### Why These Libraries?

- **`@noble/*`**: Actively maintained, audited, pure JavaScript, no Node.js dependencies
- **`cbor-x`**: Faster and more compatible than `cbor`, works in all runtimes
- **No `elliptic`**: Has known security issues, community moving away from it

## Differences from `cose-js`

1. ✅ **Runtime-agnostic** - Works in Node.js AND React Native
2. ✅ **Modern crypto** - Uses `@noble/curves` instead of `elliptic`
3. ✅ **Low-S signatures** - Enhanced security (BIP 62 compliant)
4. ✅ **Better CBOR** - Uses `cbor-x` for performance and compatibility
5. ⚠️ **Phase 1 only** - Currently supports Sign1 only (Mac, Encrypt coming later)

## Roadmap

- [x] **Phase 1**: Sign1 operations (complete!)
- [ ] **Phase 2**: Mac0/Mac operations
- [ ] **Phase 3**: Encrypt0/Encrypt operations  
- [ ] **Phase 4**: Key derivation (HKDF)
- [ ] **Phase 5**: Performance optimization

## License

Apache-2.0 (same as original `cose-js`)

## Credits

- Original [`cose-js`](https://github.com/erdtman/cose-js) by Samuel Erdtman
- Cryptography by [`@noble/curves`](https://github.com/paulmillr/noble-curves) by Paul Miller