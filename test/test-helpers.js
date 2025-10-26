/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const BN = require('bn.js');
const cbor = require('cbor-x');

/**
 * P-256 curve order (n)
 * This is the order of the P-256 elliptic curve group
 */
const P256_N = new BN('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16);

/**
 * P-384 curve order (n)
 */
const P384_N = new BN('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973', 16);

/**
 * P-521 curve order (n)
 */
const P521_N = new BN('01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409', 16);

/**
 * Converts COSE test fixture key format to noble private key format.
 *
 * Fixture format: { d: Buffer, x: Buffer, y: Buffer }
 * Noble format: Uint8Array (just the private key bytes)
 *
 * @param {Object} fixtureKey - Key from test fixture { d, x, y }
 * @returns {Uint8Array} Private key in noble format
 */
function fixturePrivateKeyToNoble (fixtureKey) {
  const d = fixtureKey.d;
  if (Buffer.isBuffer(d)) {
    return new Uint8Array(d.buffer, d.byteOffset, d.byteLength);
  }
  return d;
}

/**
 * Converts COSE test fixture public key format to noble public key format.
 *
 * Fixture format: { x: Buffer, y: Buffer }
 * Noble format: Uint8Array in uncompressed format (0x04 || x || y)
 *
 * @param {Object} fixtureKey - Key from test fixture { x, y }
 * @returns {Uint8Array} Public key in noble uncompressed format
 */
function fixturePublicKeyToNoble (fixtureKey) {
  const x = fixtureKey.x;
  const y = fixtureKey.y;

  const xBytes = Buffer.isBuffer(x) ? x : Buffer.from(x);
  const yBytes = Buffer.isBuffer(y) ? y : Buffer.from(y);

  // Uncompressed format: 0x04 || x || y
  const pubKey = new Uint8Array(1 + xBytes.length + yBytes.length);
  pubKey[0] = 0x04;
  pubKey.set(xBytes, 1);
  pubKey.set(yBytes, 1 + xBytes.length);

  return pubKey;
}

/**
 * Creates a Signer object from fixture data that implements noble's Signer interface.
 * This matches noble's default behavior and is compatible with TEE/Secure Enclave.
 *
 * Signer Interface (matches noble):
 * - sign(message: Uint8Array): Promise<Uint8Array>
 *   The signer hashes the message and then signs it (like noble's default behavior)
 *
 * @param {Object} fixtureKey - Key from test fixture { d, x, y }
 * @param {string} algorithm - COSE algorithm (e.g., 'ES256', 'ES384', 'ES512')
 * @returns {Object} Signer object with sign() method
 */
function createFixtureSigner (fixtureKey, algorithm) {
  const { p256, p384, p521 } = require('@noble/curves/nist.js');

  const curveMap = {
    ES256: p256,
    ES384: p384,
    ES512: p521
  };

  const curve = curveMap[algorithm];
  if (!curve) {
    throw new Error('Unsupported algorithm: ' + algorithm);
  }

  const privateKey = fixturePrivateKeyToNoble(fixtureKey);

  return {
    // Noble's default interface: sign(message) - hashes and signs
    sign: async (message) => {
      // Use noble's default behavior (prehash: true, hashes the message)
      return curve.sign(message, privateKey);
    }
  };
}

/**
 * Creates a Verifier object from fixture data that implements noble's Verifier interface.
 *
 * Verifier Interface (matches noble):
 * - verify(signature: Uint8Array, message: Uint8Array): Promise<boolean>
 *   The verifier hashes the message and then verifies the signature
 *
 * @param {Object} fixtureKey - Key from test fixture { x, y }
 * @param {string} algorithm - COSE algorithm (e.g., 'ES256', 'ES384', 'ES512')
 * @returns {Object} Verifier object with verify() method
 */
function createFixtureVerifier (fixtureKey, algorithm) {
  const { p256, p384, p521 } = require('@noble/curves/nist.js');

  const curveMap = {
    ES256: p256,
    ES384: p384,
    ES512: p521
  };

  const curve = curveMap[algorithm];
  if (!curve) {
    throw new Error('Unsupported algorithm: ' + algorithm);
  }

  const publicKey = fixturePublicKeyToNoble(fixtureKey);

  return {
    // Noble's default interface: verify(signature, message) - hashes and verifies
    verify: async (signature, message) => {
      // Use noble's default behavior (prehash: true, hashes the message)
      return curve.verify(signature, message, publicKey);
    }
  };
}

/**
 * Normalizes an ECDSA signature to low-S form.
 *
 * ECDSA signatures have a malleability property: for a given (r, s),
 * (r, n-s) is also a valid signature. Low-S normalization ensures
 * s < n/2 to prevent signature malleability.
 *
 * Noble/curves enforces low-S for security, but COSE test fixtures
 * use high-S (from elliptic library). This function normalizes
 * test fixture signatures to be compatible with noble.
 *
 * @param {Buffer} signature - The signature to normalize (64 bytes for P-256/P-384, 132 bytes for P-521)
 * @param {BN} curveOrder - The order (n) of the elliptic curve
 * @returns {Buffer} The normalized signature with low-S
 */
function normalizeSignatureToLowS (signature, curveOrder) {
  const rLength = Math.floor(signature.length / 2);
  const r = signature.slice(0, rLength);
  let s = signature.slice(rLength);

  // Convert s to BigNum
  const sBN = new BN(s);
  const halfN = curveOrder.shrn(1); // n / 2

  // If s > n/2, normalize to s = n - s
  if (sBN.gt(halfN)) {
    const normalizedS = curveOrder.sub(sBN);
    s = Buffer.from(normalizedS.toArray('be', rLength));
  }

  return Buffer.concat([r, s]);
}

/**
 * Normalizes a Sign1 COSE message's signature to low-S.
 * Extracts the signature from the COSE structure, normalizes it,
 * and reconstructs the COSE message.
 *
 * @param {Buffer} coseSign1Message - The complete COSE Sign1 message
 * @param {string} algorithm - The algorithm ('ES256', 'ES384', or 'ES512')
 * @returns {Buffer} The COSE message with normalized low-S signature
 */
function normalizeSign1MessageToLowS (coseSign1Message, algorithm) {
  // Decode the COSE Sign1 message
  const decoded = cbor.decode(coseSign1Message);

  // COSE Sign1 structure: [protected, unprotected, payload, signature]
  const coseArray = decoded.value || decoded;
  const signature = coseArray[3];

  // Determine curve order based on algorithm
  let curveOrder;
  if (algorithm === 'ES256' || algorithm === -7) {
    curveOrder = P256_N;
  } else if (algorithm === 'ES384' || algorithm === -35) {
    curveOrder = P384_N;
  } else if (algorithm === 'ES512' || algorithm === -36) {
    curveOrder = P521_N;
  } else {
    throw new Error('Unsupported algorithm for low-S normalization: ' + algorithm);
  }

  // Normalize the signature
  const normalizedSig = normalizeSignatureToLowS(signature, curveOrder);

  // Reconstruct the COSE array with normalized signature
  const newArray = [
    coseArray[0], // protected headers
    coseArray[1], // unprotected headers
    coseArray[2], // payload
    normalizedSig // normalized signature
  ];

  // Re-encode with the tag (18 = 0xd2 for Sign1)
  const tag = decoded.tag !== undefined ? decoded.tag : 18;
  const encoded = cbor.encode(newArray);

  // Manually prepend CBOR tag
  if (tag === 18) { // Sign1Tag
    return Buffer.concat([Buffer.from([0xd2]), encoded]);
  } else if (tag === 98) { // SignTag
    return Buffer.concat([Buffer.from([0xd8, 0x62]), encoded]);
  }

  // Fallback: just return the encoded array
  return encoded;
}

/**
 * Get the curve order for a given COSE algorithm
 */
function getCurveOrderForAlgorithm (algorithm) {
  if (algorithm === 'ES256' || algorithm === -7) {
    return P256_N;
  } else if (algorithm === 'ES384' || algorithm === -35) {
    return P384_N;
  } else if (algorithm === 'ES512' || algorithm === -36) {
    return P521_N;
  }
  throw new Error('Unsupported algorithm: ' + algorithm);
}

module.exports = {
  fixturePrivateKeyToNoble,
  fixturePublicKeyToNoble,
  createFixtureSigner,
  createFixtureVerifier,
  normalizeSignatureToLowS,
  normalizeSign1MessageToLowS,
  getCurveOrderForAlgorithm,
  P256_N,
  P384_N,
  P521_N
};
