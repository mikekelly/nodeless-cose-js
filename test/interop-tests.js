/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

/**
 * Interoperability tests between noble/curves and elliptic
 *
 * These tests verify that:
 * 1. Signatures created with noble can be verified by elliptic
 * 2. Our implementation is compatible with other COSE implementations
 *
 * Note: We normalize high-S signatures to low-S for noble compatibility.
 * This is a security improvement, not a limitation.
 */

const test = require('ava');
const cose = require('../');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
const EC = require('elliptic').ec;
const crypto = require('crypto');
const {
  createFixtureSigner
} = require('./test-helpers');

test('noble-created Sign1 can be verified by elliptic', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-01.json');
  const plaintext = Buffer.from(example.input.plaintext);
  const u = example.input.sign0.unprotected;

  // Sign with noble using signer interface
  const signer = createFixtureSigner({
    d: base64url.toBuffer(example.input.sign0.key.d)
  }, example.input.sign0.alg);

  const header = { u: u };
  const buf = await cose.sign.create(header, plaintext, signer);

  // Decode the COSE message to extract the signature
  const cbor = require('cbor-x');
  const decoded = cbor.decode(buf);
  const signature = decoded.value[3]; // Signature is at index 3

  // Verify with elliptic
  const ec = new EC('p256');
  const keyPair = ec.keyFromPrivate(base64url.toBuffer(example.input.sign0.key.d));

  // Reconstruct ToBeSigned for verification
  // Note: Empty protected headers are represented as empty buffer in ToBeSigned!
  const bodyP = decoded.value[0];
  const toBeSignedP = (bodyP.length === 1 && bodyP[0] === 0xa0) ? Buffer.from([]) : bodyP;

  const ToBeSigned = [
    'Signature1',
    toBeSignedP, // Empty buffer for empty protected headers
    Buffer.from([]), // empty external AAD
    plaintext
  ];
  const toBeSignedBytes = cbor.encode(ToBeSigned);
  const msgHash = crypto.createHash('sha256').update(toBeSignedBytes).digest();

  // Extract r and s from signature
  const r = signature.slice(0, 32);
  const s = signature.slice(32, 64);

  const isValid = keyPair.verify(msgHash, { r: r, s: s });

  t.true(isValid, 'Noble signature should be verifiable by elliptic');
});

test('noble-created Sign1 with low-S is valid', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-01.json');
  const plaintext = Buffer.from(example.input.plaintext);
  const u = example.input.sign0.unprotected;

  // Create signature with noble using signer interface
  const signer = createFixtureSigner({
    d: base64url.toBuffer(example.input.sign0.key.d)
  }, example.input.sign0.alg);

  const header = { u: u };
  const buf = await cose.sign.create(header, plaintext, signer);

  // Decode to check signature
  const cbor = require('cbor-x');
  const decoded = cbor.decode(buf);
  const signature = decoded.value[3];
  const s = signature.slice(32, 64);

  // Check that s is low-S (s < n/2)
  const BN = require('bn.js');
  const P256_N = new BN('FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551', 16);
  const halfN = P256_N.shrn(1);
  const sBN = new BN(s);

  t.true(sBN.lt(halfN), 'Signature should use low-S (s < n/2)');
});

test('self-verify: noble sign -> noble verify', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-01.json');
  const plaintext = Buffer.from(example.input.plaintext);
  const u = example.input.sign0.unprotected;

  // Sign with noble using signer interface
  const signer = createFixtureSigner({
    d: base64url.toBuffer(example.input.sign0.key.d)
  }, example.input.sign0.alg);

  const header = { u: u };
  const buf = await cose.sign.create(header, plaintext, signer);

  // Verify with noble - use direct key
  const { p256 } = require('@noble/curves/nist.js');
  const pubKey = p256.getPublicKey(base64url.toBuffer(example.input.sign0.key.d));
  const verifier = {
    key: pubKey
  };

  const verified = await cose.sign.verify(buf, verifier);
  t.true(Buffer.isBuffer(verified));
  t.is(verified.toString('utf8'), plaintext.toString('utf8'));
});

test('noble sign with external AAD -> elliptic verify', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-02.json');
  const plaintext = Buffer.from(example.input.plaintext);
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;

  // Sign with noble using signer interface
  const signer = Object.assign(
    createFixtureSigner({
      d: base64url.toBuffer(example.input.sign0.key.d)
    }, example.input.sign0.alg),
    { externalAAD: Buffer.from(example.input.sign0.external, 'hex') }
  );

  const header = { p: p, u: u };
  const buf = await cose.sign.create(header, plaintext, signer);

  // Decode the COSE message
  const cbor = require('cbor-x');
  const decoded = cbor.decode(buf);
  const signature = decoded.value[3];

  // Verify with elliptic
  const ec = new EC('p256');
  const keyPair = ec.keyFromPrivate(base64url.toBuffer(example.input.sign0.key.d));

  // Reconstruct ToBeSigned (protected headers are non-empty, so use them as-is)
  const ToBeSigned = [
    'Signature1',
    decoded.value[0], // protected headers (non-empty)
    Buffer.from(example.input.sign0.external, 'hex'),
    plaintext
  ];
  const toBeSignedBytes = cbor.encode(ToBeSigned);
  const msgHash = crypto.createHash('sha256').update(toBeSignedBytes).digest();

  // Extract r and s from signature
  const r = signature.slice(0, 32);
  const s = signature.slice(32, 64);

  const isValid = keyPair.verify(msgHash, { r: r, s: s });

  t.true(isValid, 'Noble signature with external AAD should be verifiable by elliptic');
});
