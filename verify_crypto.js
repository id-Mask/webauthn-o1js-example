import {
  parseAttestationObject,
  verifyP256Point,
} from './utils.js';
import { credential, assertion } from './webauthn.js';
import crypto from 'crypto';

// Parse the saved attestation object to get the public key
const publicKey = parseAttestationObject(credential.response.attestationObject);

console.log(publicKey);
console.log(verifyP256Point(publicKey.x, publicKey.y));

// Convert the JWK-style public key to DER format
const publicKeyDer = crypto.createPublicKey({
  key: {
    crv: 'P-256',
    kty: 'EC',
    x: publicKey.x,
    y: publicKey.y,
  },
  format: 'jwk',
});

// Recreate the signed data
const authDataBuffer = Buffer.from(assertion.response.authenticatorData, 'base64');
const clientDataHash = crypto
  .createHash('sha256')
  .update(Buffer.from(assertion.response.clientDataJSON, 'base64'))
  .digest();

// Concatenate authenticatorData and clientDataHash
const signedData = Buffer.concat([authDataBuffer, clientDataHash]);

// Convert signature from base64 to buffer
const signatureBuffer = Buffer.from(assertion.response.signature, 'base64');

// Verify the signature
const isValid = crypto.verify(
  'sha256',
  signedData,
  publicKeyDer,
  signatureBuffer
)

console.log('signature is valid:', isValid)

