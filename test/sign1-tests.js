/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const test = require('ava');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
const cbor = require('cbor-x');
const { deepEqual } = require('./util.js');
const {
  createFixtureSigner,
  createFixtureVerifier,
  normalizeSign1MessageToLowS
} = require('./test-helpers');

test('create sign-pass-01', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-01.json');
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signer = createFixtureSigner({
    d: base64url.toBuffer(example.input.sign0.key.d)
  }, example.input.sign0.alg);

  const header = { u: u };
  const buf = await cose.sign.create(header, plaintext, signer);
  t.true(Buffer.isBuffer(buf));
  t.true(buf.length > 0);

  // Decode and check structure
  const actual = cbor.decode(buf);
  const expected = cbor.decode(Buffer.from(example.output.cbor, 'hex'));

  // Check that it's a tagged Sign1 message
  t.is(actual.tag, expected.tag);
  t.is(actual.value.length, expected.value.length);

  // Check protected headers (actual.value[0])
  t.true(Buffer.compare(actual.value[0], expected.value[0]) === 0);

  // Check unprotected headers (actual.value[1])
  // Note: cbor-x decodes as Map, test vectors show as object - both are valid
  const actualU = actual.value[1];
  const expectedU = expected.value[1];
  if (actualU instanceof Map) {
    t.is(actualU.get(1), expectedU[1] || expectedU['1']);
    t.true(Buffer.compare(actualU.get(4), expectedU[4] || expectedU['4']) === 0);
  } else {
    t.true(deepEqual(actualU, expectedU));
  }

  // Check payload (actual.value[2])
  t.true(Buffer.compare(actual.value[2], expected.value[2]) === 0);

  // We don't compare signatures as ECDSA is non-deterministic
  // Instead, verify that the signature validates
  const verifier = createFixtureVerifier({
    x: base64url.toBuffer(example.input.sign0.key.x),
    y: base64url.toBuffer(example.input.sign0.key.y)
  }, example.input.sign0.alg);
  const verified = await cose.sign.verify(buf, verifier);
  t.true(Buffer.isBuffer(verified));
  t.is(verified.toString('utf8'), example.input.plaintext);
});

test('create sign-pass-02', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-02.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signer = Object.assign(
    createFixtureSigner({
      d: base64url.toBuffer(example.input.sign0.key.d)
    }, example.input.sign0.alg),
    { externalAAD: Buffer.from(example.input.sign0.external, 'hex') }
  );

  const header = { p: p, u: u };
  const buf = await cose.sign.create(header, plaintext, signer);
  t.true(Buffer.isBuffer(buf));
  t.true(buf.length > 0);

  // Verify that the signature validates
  const verifier = Object.assign(
    createFixtureVerifier({
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    }, example.input.sign0.alg),
    { externalAAD: Buffer.from(example.input.sign0.external, 'hex') }
  );
  const verified = await cose.sign.verify(buf, verifier);
  t.true(Buffer.isBuffer(verified));
  t.is(verified.toString('utf8'), example.input.plaintext);
});

test('create sign-pass-03', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-03.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signer = createFixtureSigner({
    d: base64url.toBuffer(example.input.sign0.key.d)
  }, example.input.sign0.alg);

  const header = { p: p, u: u };
  const options = { excludetag: true };
  const buf = await cose.sign.create(header, plaintext, signer, options);
  t.true(Buffer.isBuffer(buf));
  t.true(buf.length > 0);

  // Verify that the signature validates
  const verifier = createFixtureVerifier({
    x: base64url.toBuffer(example.input.sign0.key.x),
    y: base64url.toBuffer(example.input.sign0.key.y)
  }, example.input.sign0.alg);
  const options2 = { defaultType: cose.sign.Sign1Tag };
  const verified = await cose.sign.verify(buf, verifier, options2);
  t.true(Buffer.isBuffer(verified));
  t.is(verified.toString('utf8'), example.input.plaintext);
});

test('verify sign-pass-01', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-01.json');

  const verifier = createFixtureVerifier({
    x: base64url.toBuffer(example.input.sign0.key.x),
    y: base64url.toBuffer(example.input.sign0.key.y)
  }, example.input.sign0.alg);

  // Test fixture uses high-S signature (from elliptic)
  // Normalize to low-S for noble compatibility
  const signature = Buffer.from(example.output.cbor, 'hex');
  const normalizedSignature = normalizeSign1MessageToLowS(signature, example.input.sign0.alg);

  const buf = await cose.sign.verify(normalizedSignature, verifier);
  t.true(Buffer.isBuffer(buf));
  t.true(buf.length > 0);
  t.is(buf.toString('utf8'), example.input.plaintext);
});

test('verify sign-pass-02', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-02.json');

  const verifier = Object.assign(
    createFixtureVerifier({
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    }, example.input.sign0.alg), // Use algorithm from fixture
    { externalAAD: Buffer.from(example.input.sign0.external, 'hex') }
  );

  // Test fixture uses high-S signature (from elliptic)
  // Normalize to low-S for noble compatibility
  const signature = Buffer.from(example.output.cbor, 'hex');
  const normalizedSignature = normalizeSign1MessageToLowS(signature, example.input.sign0.alg);

  const buf = await cose.sign.verify(normalizedSignature, verifier);
  t.true(Buffer.isBuffer(buf));
  t.true(buf.length > 0);
  t.is(buf.toString('utf8'), example.input.plaintext);
});

test('verify sign-pass-03', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-03.json');

  const verifier = createFixtureVerifier({
    x: base64url.toBuffer(example.input.sign0.key.x),
    y: base64url.toBuffer(example.input.sign0.key.y)
  }, example.input.sign0.alg);

  const signature = Buffer.from(example.output.cbor, 'hex');
  const normalizedSignature = normalizeSign1MessageToLowS(signature, example.input.sign0.alg);

  const options = { defaultType: cose.sign.Sign1Tag };
  const buf = await cose.sign.verify(normalizedSignature, verifier, options);
  t.true(Buffer.isBuffer(buf));
  t.true(buf.length > 0);
  t.is(buf.toString('utf8'), example.input.plaintext);
});

test('verify sign-fail-01', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-01.json');

  const verifier = createFixtureVerifier({
    x: base64url.toBuffer(example.input.sign0.key.x),
    y: base64url.toBuffer(example.input.sign0.key.y)
  }, example.input.sign0.alg);

  const signature = Buffer.from(example.output.cbor, 'hex');
  try {
    await cose.sign.verify(signature, verifier);
    t.fail('Unexpected cbor tag, \'998\'');
  } catch (error) {
    t.is(error.message, 'Unexpected cbor tag, \'998\'');
  }
});

test('verify sign-fail-02', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-02.json');

  const verifier = createFixtureVerifier({
    x: base64url.toBuffer(example.input.sign0.key.x),
    y: base64url.toBuffer(example.input.sign0.key.y)
  }, example.input.sign0.alg);

  const signature = Buffer.from(example.output.cbor, 'hex');
  try {
    await cose.sign.verify(signature, verifier);
    t.fail('Signature missmatch');
  } catch (error) {
    t.is(error.message, 'Signature missmatch');
  }
});

test('verify sign-fail-03', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-03.json');

  const verifier = createFixtureVerifier({
    x: base64url.toBuffer(example.input.sign0.key.x),
    y: base64url.toBuffer(example.input.sign0.key.y)
  }, example.input.sign0.alg);

  const signature = Buffer.from(example.output.cbor, 'hex');
  try {
    await cose.sign.verify(signature, verifier);
    t.fail('Unknown algorithm, -999');
  } catch (error) {
    t.is(error.message, 'Unknown algorithm, -999');
  }
});

test('verify sign-fail-04', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-04.json');

  const verifier = createFixtureVerifier({
    x: base64url.toBuffer(example.input.sign0.key.x),
    y: base64url.toBuffer(example.input.sign0.key.y)
  }, example.input.sign0.alg);

  const signature = Buffer.from(example.output.cbor, 'hex');
  try {
    await cose.sign.verify(signature, verifier);
    t.fail('Unknown algorithm, unknown');
  } catch (error) {
    t.is(error.message, 'Unknown algorithm, unknown');
  }
});

test('verify sign-fail-06', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-06.json');

  const verifier = createFixtureVerifier({
    x: base64url.toBuffer(example.input.sign0.key.x),
    y: base64url.toBuffer(example.input.sign0.key.y)
  }, example.input.sign0.alg);

  const signature = Buffer.from(example.output.cbor, 'hex');
  try {
    await cose.sign.verify(signature, verifier);
    t.fail('Signature missmatch');
  } catch (error) {
    t.is(error.message, 'Signature missmatch');
  }
});

test('verify sign-fail-07', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-07.json');

  const verifier = createFixtureVerifier({
    x: base64url.toBuffer(example.input.sign0.key.x),
    y: base64url.toBuffer(example.input.sign0.key.y)
  }, example.input.sign0.alg);

  const signature = Buffer.from(example.output.cbor, 'hex');
  try {
    await cose.sign.verify(signature, verifier);
    t.fail('Signature missmatch');
  } catch (error) {
    t.is(error.message, 'Signature missmatch');
  }
});
