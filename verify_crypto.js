import {
  parseAttestationObject,
  verifyWebAuthnSignature,
  verifyP256Point,
} from './utils.js';
import { credential, assertion } from './webauthnData.js';
import crypto from 'crypto';

// Parse the saved attestation object to get the public key
const publicKey = parseAttestationObject(credential.response.attestationObject);

console.log(publicKey);
console.log(verifyP256Point(publicKey.x, publicKey.y));

const publicKeyDer = crypto.createPublicKey({
  key: publicKey,
  format: 'jwk',
});

console.log(publicKeyDer);

// Verify the signature
const isValid = await verifyWebAuthnSignature({
  publicKey,
  authenticatorData: assertion.response.authenticatorData,
  clientDataJSON: assertion.response.clientDataJSON,
  signature: assertion.response.signature,
});

console.log(isValid);

/*
  Lets verify using o1js 
*/

