const cose = require('../');
const { p256 } = require('@noble/curves/nist.js');

async function run () {
  try {
    // Example 1: Create a Sign1 message with noble keys
    console.log('Example 1: Create Sign1 message with noble');
    const plaintext = 'Important message!';
    const headers = {
      p: { alg: 'ES256' },
      u: { kid: '11' }
    };

    // Generate a random private key (or use an existing one)
    const privateKey = p256.utils.randomPrivateKey
      ? p256.utils.randomPrivateKey()
      : Buffer.from('6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19', 'hex');
    const publicKey = p256.getPublicKey(privateKey);

    // Create signer (uses noble's default interface)
    const signer = {
      key: privateKey
    };

    const buf = await cose.sign.create(headers, plaintext, signer);
    console.log('✓ Signed message: ' + buf.toString('hex').substring(0, 80) + '...\n');

    // Example 2: Verify the message we just created
    console.log('Example 2: Verify Sign1 message');
    const verifier = {
      key: publicKey
    };

    const verified = await cose.sign.verify(buf, verifier);
    console.log('✓ Verified message: ' + verified.toString('utf8') + '\n');

    // Example 3: Using custom signer interface (for TEE/Secure Enclave)
    console.log('Example 3: Custom signer interface (TEE-compatible)');

    // This is what your TEE wrapper would look like:
    const customSigner = {
      sign: async (message) => {
        // In a real TEE implementation, this would call:
        // await SecureEnclave.signMessage(keyId, message);
        // For demo, we just use noble directly
        return p256.sign(message, privateKey);
      }
    };

    const buf2 = await cose.sign.create(headers, plaintext, customSigner);
    console.log('✓ Signed with custom signer: ' + buf2.toString('hex').substring(0, 80) + '...\n');

    // Example 4: Sign with external AAD
    console.log('Example 4: Sign with external AAD');
    const signerWithAAD = {
      key: privateKey,
      externalAAD: Buffer.from('some-external-data')
    };

    const buf3 = await cose.sign.create(headers, plaintext, signerWithAAD);
    console.log('✓ Signed with external AAD\n');

    // Verify with the same external AAD
    const verifierWithAAD = {
      key: publicKey,
      externalAAD: Buffer.from('some-external-data')
    };

    const verified2 = await cose.sign.verify(buf3, verifierWithAAD);
    console.log('✓ Verified with external AAD: ' + verified2.toString('utf8') + '\n');

    console.log('All examples completed successfully! 🎉');
  } catch (error) {
    console.error('Error:', error.message);
    console.error(error.stack);
  }
}

run();
