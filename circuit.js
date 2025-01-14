// https://github.com/o1-labs/o1js/blob/996ebb3119ec087a0badc16ea8036766cb68d3fb/src/lib/provable/test/ecdsa.unit-test.ts#L36-L75
// https://github.com/o1-labs/o1js/blob/996ebb3119ec087a0badc16ea8036766cb68d3fb/src/lib/provable/test/ecdsa.unit-test.ts#L274

import {
  Struct,
  ZkProgram,
  Crypto,
  createForeignCurve,
  createEcdsa,
  Bool,
  Bytes,
} from 'o1js';
import { parseAttestationObject } from './utils.js';
import { credential, assertion } from './webauthnData.js';
import crypto from 'crypto'
import * as ox from 'ox';


export class Bytes69 extends Bytes(69) {}
export class Secp256r1 extends createForeignCurve(Crypto.CurveParams.Secp256r1) {}
export class EcdsaP256 extends createEcdsa(Secp256r1) {}

export class VerifyParams extends Struct({
  payload: Bytes69,
  publicKey: Secp256r1,
  signature: EcdsaP256,
}) {}

export const WebAuthnP256 = ZkProgram({
  name: 'webauthn-p256',
  publicInput: VerifyParams,
  publicOutput: Bool,
  methods: {
    verifySignature: {
      privateInputs: [],
      async method(params) {
        const { payload, publicKey, signature } = params;
        return {
          publicOutput: signature.verify(payload, publicKey),
        };
      },
    },
  },
});

// ----------------------------- //
// parse public key

const publicKey = parseAttestationObject(credential.response.attestationObject);

// Utility to decode Base64 URL to a Buffer
const base64UrlDecode = (base64Url) => {
  // Replace Base64 URL characters
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  // Add padding if necessary
  const padding = '='.repeat((4 - (base64.length % 4)) % 4);
  const base64Padded = base64 + padding;
  return Buffer.from(base64Padded, 'base64');
}

// Decode x and y
const xBuffer = base64UrlDecode(publicKey.x);
const yBuffer = base64UrlDecode(publicKey.y);

// Ensure both x and y are 32 bytes as expected for P-256
if (xBuffer.length !== 32 || yBuffer.length !== 32) {
  throw new Error('Invalid x or y length for P-256 curve.');
}

// Create the uncompressed point buffer
const uncompressedPoint = Buffer.concat([Buffer.from([0x04]), xBuffer, yBuffer]);
const uncompressedPointHex = uncompressedPoint.toString('hex');

// log
console.log(publicKey);
console.log(Secp256r1.fromHex(uncompressedPointHex))

// ----------------------------- //
// parse signature

// signature
console.log(assertion.response.signature)
console.log(EcdsaP256.fromHex('0x' + Buffer.from(assertion.response.signature, 'base64').toString('hex')))

// ----------------------------- //
// parse payload

const mergeBuffers = (buffer1, buffer2) => {
  const merged = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  merged.set(new Uint8Array(buffer1), 0);
  merged.set(new Uint8Array(buffer2), buffer1.byteLength);
  return merged.buffer;
};

// Decode and hash clientDataJSON
console.log(assertion.response.clientDataJSON);

const clientDataJSON = Buffer.from(assertion.response.clientDataJSON, 'base64');
const hashedClientDataJSON = await crypto.subtle.digest('SHA-256', clientDataJSON);

// Decode authenticatorData
const authenticatorData = Buffer.from(assertion.response.authenticatorData, 'base64');

// Merge authenticatorData and hashed clientDataJSON
const payloadBuffer = mergeBuffers(authenticatorData, hashedClientDataJSON);

// Convert ArrayBuffer to hex string
const bufferToHex = (buffer) => {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
};

const payloadHex = bufferToHex(payloadBuffer);

console.log(payloadHex);

// Example usage of Bytes32
console.log(Bytes69.fromHex(payloadHex));

// -------------------------- //
// verify in ox
const oxResult = ox.P256.verify({
  hash: false,
  publicKey: ox.PublicKey.fromHex(uncompressedPointHex),
  payload: ox.Bytes.fromHex(ox.Hash.sha256(payloadHex)),
  signature: ox.Signature.fromHex('0x' + Buffer.from(assertion.response.signature, 'base64').toString('hex')),
});
console.log('OX P256 valid', oxResult);

// -------------------------- //

await WebAuthnP256.compile()
const valid = await WebAuthnP256.verifySignature({
  payload: Bytes69.fromHex(payloadHex),
  publicKey: Secp256r1.fromHex(uncompressedPointHex),
  signature: EcdsaP256.fromHex('0x' + Buffer.from(assertion.response.signature, 'base64').toString('hex')),
})

console.log('O1 P256 valid', valid.proof.publicOutput.toBoolean());