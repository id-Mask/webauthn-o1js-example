// Option 1: ES Modules
import crypto from 'crypto';
import jose from 'node-jose';

async function convertKey() {
  const publicKey = {
    kty: 'EC',
    crv: 'P-256',
    x: '5O4qgyA83JJZJxUkoab83U5x5iSRU1ZVK0A4phUXm88',
    y: 'ofqW9DtjY4kzqUpXT5VpziI_1braUKnshw3uEiOfH7Q',
  };

  const keystore = jose.JWK.createKeyStore();
  const key = await keystore.add(publicKey);
  const pemKey = key.toPEM(false);

  console.log(pemKey);

  const publicKeyDer = crypto.createPublicKey(pemKey);
  console.log(publicKeyDer);
}

convertKey();
