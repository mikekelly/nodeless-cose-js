/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor-x');
const { p256, p384, p521 } = require('@noble/curves/nist.js');
const { sha256, sha384, sha512 } = require('@noble/hashes/sha2.js');
const common = require('./common');
const EMPTY_BUFFER = common.EMPTY_BUFFER;

// Configure cbor-x to use Maps (not plain objects) for CBOR maps
cbor.mapsAsObjects = false;

const SignTag = exports.SignTag = 98;
const Sign1Tag = exports.Sign1Tag = 18;

const AlgFromTags = {};
AlgFromTags[-7] = { sign: 'ES256', digest: 'SHA-256' };
AlgFromTags[-35] = { sign: 'ES384', digest: 'SHA-384' };
AlgFromTags[-36] = { sign: 'ES512', digest: 'SHA-512' };
AlgFromTags[-37] = { sign: 'PS256', digest: 'SHA-256' };
AlgFromTags[-38] = { sign: 'PS384', digest: 'SHA-384' };
AlgFromTags[-39] = { sign: 'PS512', digest: 'SHA-512' };
AlgFromTags[-257] = { sign: 'RS256', digest: 'SHA-256' };
AlgFromTags[-258] = { sign: 'RS384', digest: 'SHA-384' };
AlgFromTags[-259] = { sign: 'RS512', digest: 'SHA-512' };

const COSEAlgToNoble = {
  ES256: { curve: p256, hash: sha256 },
  ES384: { curve: p384, hash: sha384 },
  ES512: { curve: p521, hash: sha512 }
};

// Helper to convert Buffer to Uint8Array if needed
function toUint8Array (buf) {
  if (buf instanceof Uint8Array) {
    return buf;
  }
  if (Buffer.isBuffer(buf)) {
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  throw new Error('Expected Buffer or Uint8Array');
}

async function doSign (SigStructure, signer, alg) {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }

  const algName = AlgFromTags[alg].sign;

  // Check if this is an RSA algorithm (not supported in Phase 1)
  if (algName.startsWith('RS') || algName.startsWith('PS')) {
    throw new Error('RSA algorithms not supported in Phase 1: ' + algName);
  }

  if (!COSEAlgToNoble[algName]) {
    throw new Error('Unsupported algorithm, ' + algName);
  }

  const ToBeSigned = cbor.encode(SigStructure);

  let sig;
  if (algName.startsWith('ES')) {
    const { curve } = COSEAlgToNoble[algName];

    // Check if signer implements the sign interface (for TEE/Secure Enclave)
    if (typeof signer.sign === 'function') {
      // Pass raw ToBeSigned bytes to signer (not hashed)
      // The signer is responsible for hashing AND signing
      // This matches noble's default behavior and TEE/Secure Enclave behavior
      sig = await signer.sign(toUint8Array(ToBeSigned));
    } else if (signer.key) {
      // Direct key usage - use noble's default behavior (hashes then signs)
      const privKeyBytes = toUint8Array(signer.key);

      // Don't pass prehash: false, let noble hash the message for us
      // This matches the signer interface behavior
      const signature = curve.sign(toUint8Array(ToBeSigned), privKeyBytes);

      // Signature is a Uint8Array in compact format (r || s) with low-S
      sig = Buffer.from(signature);
    } else {
      throw new Error('Signer must have either a sign() method or a key property');
    }
  } else {
    throw new Error('Unsupported algorithm type: ' + algName);
  }

  return sig;
}

exports.create = async function (headers, payload, signers, options) {
  options = options || {};
  let u = headers.u || {};
  let p = headers.p || {};

  p = common.TranslateHeaders(p);
  u = common.TranslateHeaders(u);
  let bodyP = p || {};
  // For Sign1 message: encode empty map as A0, non-empty maps normally
  if (bodyP.size === 0) {
    bodyP = Buffer.from([0xa0]); // CBOR empty map for Sign1 structure
  } else {
    bodyP = cbor.encode(bodyP);
  }
  // For ToBeSigned: use empty buffer if protected is empty, otherwise use the encoded bytes
  const toBeSignedP = (bodyP.length === 1 && bodyP[0] === 0xa0) ? EMPTY_BUFFER : bodyP;
  if (Array.isArray(signers)) {
    if (signers.length === 0) {
      throw new Error('There has to be at least one signer');
    }
    if (signers.length > 1) {
      throw new Error('Only one signer is supported');
    }
    // TODO handle multiple signers
    const signer = signers[0];
    const externalAAD = signer.externalAAD || EMPTY_BUFFER;
    let signerP = signer.p || {};
    let signerU = signer.u || {};

    signerP = common.TranslateHeaders(signerP);
    signerU = common.TranslateHeaders(signerU);
    const alg = signerP.get(common.HeaderParameters.alg);
    signerP = (signerP.size === 0) ? EMPTY_BUFFER : cbor.encode(signerP);

    const SigStructure = [
      'Signature',
      toBeSignedP,
      signerP,
      externalAAD,
      payload
    ];

    const sig = await doSign(SigStructure, signer, alg);
    // bodyP is already the correctly encoded protected headers
    const signed = [bodyP, u, payload, [[signerP, signerU, sig]]];

    // cbor-x doesn't have Tagged class like cbor, manually construct tagged CBOR
    if (options.excludetag) {
      return Buffer.from(cbor.encode(signed));
    } else {
      // Tag 98 (SignTag) needs to be manually constructed
      const encoded = cbor.encode(signed);
      // Tag 98 in CBOR: major type 6, value 98-24 = 74 = 0x4A, so 0xd8 0x62
      const result = Buffer.concat([Buffer.from([0xd8, 0x62]), encoded]);
      return result;
    }
  } else {
    const signer = signers;
    const externalAAD = signer.externalAAD || EMPTY_BUFFER;
    const alg = p.get(common.HeaderParameters.alg) || u.get(common.HeaderParameters.alg);
    const SigStructure = [
      'Signature1',
      toBeSignedP,
      externalAAD,
      payload
    ];
    const sig = await doSign(SigStructure, signer, alg);
    // bodyP is already the correctly encoded protected headers
    const signed = [bodyP, u, payload, sig];

    // For cbor-x, manually construct CBOR tagged structure
    if (options.excludetag) {
      return Buffer.from(cbor.encode(signed));
    } else {
      // Tag 18 (Sign1Tag) in CBOR is encoded as 0xd2 followed by the content
      const encoded = cbor.encode(signed);
      const result = Buffer.concat([Buffer.from([0xd2]), encoded]);
      return result;
    }
  }
};

async function doVerify (SigStructure, verifier, alg, sig) {
  if (!AlgFromTags[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }

  const algName = AlgFromTags[alg].sign;

  // Check if this is an RSA algorithm (not supported in Phase 1)
  if (algName.startsWith('RS') || algName.startsWith('PS')) {
    throw new Error('RSA algorithms not supported in Phase 1: ' + algName);
  }

  const nobleAlg = COSEAlgToNoble[algName];
  if (!nobleAlg) {
    throw new Error('Unsupported algorithm, ' + algName);
  }

  const ToBeSigned = cbor.encode(SigStructure);

  if (algName.startsWith('ES')) {
    const { curve } = nobleAlg;
    const sigBytes = toUint8Array(sig);

    // Check if verifier implements the verify interface
    if (typeof verifier.verify === 'function') {
      // Pass raw ToBeSigned bytes to verifier (not hashed)
      // The verifier is responsible for hashing AND verifying
      const isValid = await verifier.verify(sigBytes, toUint8Array(ToBeSigned));
      if (!isValid) {
        throw new Error('Signature missmatch');
      }
    } else if (verifier.key) {
      // Direct key usage - use noble's default behavior (hashes then verifies)
      const pubKey = toUint8Array(verifier.key);

      // Don't pass prehash: false, let noble hash the message for us
      const isValid = curve.verify(sigBytes, toUint8Array(ToBeSigned), pubKey);

      if (!isValid) {
        throw new Error('Signature missmatch');
      }
    } else {
      throw new Error('Verifier must have either a verify() method or a key property');
    }
  } else {
    throw new Error('Unsupported algorithm type: ' + algName);
  }
}

function getSigner (signers, verifier) {
  for (let i = 0; i < signers.length; i++) {
    const kid = signers[i][1].get(common.HeaderParameters.kid); // TODO create constant for header locations
    if (kid.equals(Buffer.from(verifier.key.kid, 'utf8'))) {
      return signers[i];
    }
  }
}

function getCommonParameter (first, second, parameter) {
  let result;
  // Handle both Map and plain object
  if (first) {
    if (first.get) {
      result = first.get(parameter);
    } else if (typeof first === 'object') {
      // Try both numeric and string keys (cbor-x decodes maps with string keys)
      result = first[parameter] || first[String(parameter)];
    }
  }
  if (!result && second) {
    if (second.get) {
      result = second.get(parameter);
    } else if (typeof second === 'object') {
      // Try both numeric and string keys (cbor-x decodes maps with string keys)
      result = second[parameter] || second[String(parameter)];
    }
  }
  return result;
}

exports.verify = async function (payload, verifier, options) {
  options = options || {};
  const obj = cbor.decode(payload);
  return await verifyInternal(verifier, options, obj);
};

exports.verifySync = async function (payload, verifier, options) {
  options = options || {};
  const obj = cbor.decode(payload);
  return await verifyInternal(verifier, options, obj);
};

async function verifyInternal (verifier, options, obj) {
  options = options || {};
  let type = options.defaultType ? options.defaultType : SignTag;

  // cbor-x returns tagged values as objects with tagValue property
  // or we need to manually detect the tag from the raw CBOR
  // For simplicity, check if it's a TaggedValue from cbor-x
  if (obj && typeof obj === 'object' && obj.constructor && obj.constructor.name === 'Tag') {
    const tag = obj.tag;
    if (tag !== SignTag && tag !== Sign1Tag) {
      throw new Error('Unexpected cbor tag, \'' + tag + '\'');
    }
    type = tag;
    obj = obj.value;
  }

  if (!Array.isArray(obj)) {
    throw new Error('Expecting Array');
  }

  if (obj.length !== 4) {
    throw new Error('Expecting Array of lenght 4');
  }

  const [p, u, plaintext, signers] = obj;

  if (type === SignTag && !Array.isArray(signers)) {
    throw new Error('Expecting signature Array');
  }

  // Keep p as raw bytes for SigStructure, decode only for getting parameters
  const pBytes = p;
  const pDecoded = (!p.length) ? EMPTY_BUFFER : cbor.decode(p);
  // For ToBeSigned: use empty buffer if protected is empty map (A0), otherwise use raw bytes
  const toBeSignedP = (pBytes.length === 1 && pBytes[0] === 0xa0) ? EMPTY_BUFFER : pBytes;
  // Don't overwrite u - it's already decoded by cbor-x
  // u = (!u.size) ? EMPTY_BUFFER : u;  // This line was breaking it!

  const signer = (type === SignTag ? getSigner(signers, verifier) : signers);

  if (!signer) {
    throw new Error('Failed to find signer with kid' + verifier.key.kid);
  }

  if (type === SignTag) {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
    let [signerP, , sig] = signer;
    signerP = (!signerP.length) ? EMPTY_BUFFER : signerP;
    const signerPMap = cbor.decode(signerP);
    const alg = signerPMap.get(common.HeaderParameters.alg);
    const SigStructure = [
      'Signature',
      toBeSignedP,
      signerP,
      externalAAD,
      plaintext
    ];
    await doVerify(SigStructure, verifier, alg, sig);
    return plaintext;
  } else {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;

    const alg = getCommonParameter(pDecoded, u, common.HeaderParameters.alg);
    const SigStructure = [
      'Signature1',
      toBeSignedP,
      externalAAD,
      plaintext
    ];
    await doVerify(SigStructure, verifier, alg, signer);
    return plaintext;
  }
}
