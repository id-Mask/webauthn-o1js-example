// https://github.com/o1-labs/o1js/blob/996ebb3119ec087a0badc16ea8036766cb68d3fb/src/lib/provable/test/ecdsa.unit-test.ts#L36-L75
// https://github.com/o1-labs/o1js/blob/996ebb3119ec087a0badc16ea8036766cb68d3fb/src/lib/provable/test/ecdsa.unit-test.ts#L274

import { parseAttestationObject } from './utils.js';
import { credential, assertion } from './webauthnData.js';
import crypto from 'crypto'
import * as ox from 'ox';

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

// ----------------------------- //
// parse signature

function mergeBuffers(buffer1, buffer2) {
  const tmp = new Uint8Array(buffer1.byteLength + buffer2.byteLength);
  tmp.set(new Uint8Array(buffer1), 0);
  tmp.set(new Uint8Array(buffer2), buffer1.byteLength);
  return tmp.buffer;
}

function readAsn1IntegerSequence(input) {
  if (input[0] !== 0x30) throw new Error('Input is not an ASN.1 sequence');
  const seqLength = input[1];
  const elements = [];


  let current = input.slice(2, 2 + seqLength);
  while (current.length > 0) {
    const tag = current[0];
    if (tag !== 0x02) throw new Error('Expected ASN.1 sequence element to be an INTEGER');


    const elLength = current[1];
    elements.push(current.slice(2, 2 + elLength));


    current = current.slice(2 + elLength);
  }
  return elements;
}

function convertEcdsaAsn1Signature(input) {
  const elements = readAsn1IntegerSequence(input);
  if (elements.length !== 2) throw new Error('Expected 2 ASN.1 sequence elements');
  let [r, s] = elements;


  // R and S length is assumed multiple of 128bit.
  // If leading is 0 and modulo of length is 1 byte then
  // leading 0 is for two's complement and will be removed.
  if (r[0] === 0 && r.byteLength % 16 == 1) {
    r = r.slice(1);
  }
  if (s[0] === 0 && s.byteLength % 16 == 1) {
    s = s.slice(1);
  }


  // R and S length is assumed multiple of 128bit.
  // If missing a byte then it will be padded by 0.
  if ((r.byteLength % 16) == 15) {
    r = new Uint8Array(mergeBuffers(new Uint8Array([0]), r));
  }
  if ((s.byteLength % 16) == 15) {
    s = new Uint8Array(mergeBuffers(new Uint8Array([0]), s));
  }


  // If R and S length is not still multiple of 128bit,
  // then error
  if (r.byteLength % 16 != 0) throw Error("unknown ECDSA sig r length error");
  if (s.byteLength % 16 != 0) throw Error("unknown ECDSA sig s length error");


  return mergeBuffers(r, s);
}

function convertEcdsaAsn1SignatureImproved(input) {
  const elements = readAsn1IntegerSequence(input);
  if (elements.length !== 2) throw new Error('Expected 2 ASN.1 sequence elements');
  let [r, s] = elements;
  
  // Each component should be 32 bytes for P-256
  const targetLength = 32;
  
  // Handle leading zeros properly
  r = r[0] === 0 ? r.slice(1) : r;
  s = s[0] === 0 ? s.slice(1) : s;
  
  // Pad if shorter than 32 bytes
  if (r.length < targetLength) {
    r = Buffer.concat([Buffer.alloc(targetLength - r.length, 0), r]);
  }
  if (s.length < targetLength) {
    s = Buffer.concat([Buffer.alloc(targetLength - s.length, 0), s]);
  }
  
  // Verify final lengths
  if (r.length !== targetLength || s.length !== targetLength) {
    throw new Error(`Invalid R or S length. Expected ${targetLength} bytes each`);
  }
  
  return Buffer.concat([r, s]);
}


const signature = convertEcdsaAsn1SignatureImproved(new Uint8Array(base64UrlDecode(assertion.response.signature)));

// Convert ArrayBuffer to hex string
const bufferToHex = (buffer) => {
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('');
};

// signature
console.log(assertion.response.signature)
console.log(signature)

// ----------------------------- //
// parse payload

// Decode and hash clientDataJSON
console.log(assertion.response.clientDataJSON);

const clientDataJSON = Buffer.from(assertion.response.clientDataJSON, 'base64');
const hashedClientDataJSON = crypto.createHash('sha256').update(clientDataJSON).digest();

// Decode authenticatorData
const authenticatorData = Buffer.from(assertion.response.authenticatorData, 'base64');

// merge and hash
const payload = Buffer.concat([authenticatorData, hashedClientDataJSON]);
const hashedPayload = crypto.createHash('sha256').update(payload).digest();
const payloadHex = hashedPayload.toString('hex');

console.log('payload hex:', payloadHex);

// -------------------------- //
// verify in ox
const oxResult = ox.P256.verify({
  hash: false,
  publicKey: ox.PublicKey.fromHex('0x' + uncompressedPointHex),
  payload: ox.Bytes.fromHex('0x' + payloadHex),
  signature: ox.Signature.fromHex('0x' + bufferToHex(signature)),
});
console.log('OX P256 valid', oxResult);

