import cbor from 'cbor';
import { Buffer } from 'buffer';
import * as crypto from 'crypto';

export const parseAttestationObject = (attestationObject) => {
  // First decode the base64 to get the raw bytes
  const attestationBuffer = Buffer.from(attestationObject, 'base64');

  // Decode the CBOR
  const attestationCbor = cbor.decodeFirstSync(attestationBuffer);

  // Get the authData from the attestation
  const { authData } = attestationCbor;

  // The public key starts after:
  // 32 bytes of RP ID hash
  // 1 byte of flags
  // 4 bytes of signature counter
  // 16 bytes of AAGUID
  // 2 bytes of credential ID length (L)
  // L bytes of credential ID
  let position = 32 + 1 + 4;

  // Skip AAGUID
  position += 16;

  // Get credential ID length
  const credentialIdLength = (authData[position] << 8) | authData[position + 1];
  position += 2;

  // Skip credential ID
  position += credentialIdLength;

  // The rest is the CBOR-encoded public key
  const publicKeyCose = authData.slice(position);
  const publicKeyObject = cbor.decodeFirstSync(publicKeyCose);

  // COSE key to JWK conversion
  // For ES256 (ECDSA with P-256 curve)
  const x = publicKeyObject.get(-2); // X coordinate
  const y = publicKeyObject.get(-3); // Y coordinate

  return {
    kty: 'EC',
    crv: 'P-256',
    x: Buffer.from(x).toString('base64url'),
    y: Buffer.from(y).toString('base64url'),
    ext: true,
  };
};

export const verifyWebAuthnSignature = async ({
  publicKey,
  authenticatorData,
  clientDataJSON,
  signature,
}) => {
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
  const authDataBuffer = Buffer.from(authenticatorData, 'base64');
  const clientDataHash = crypto
    .createHash('sha256')
    .update(Buffer.from(clientDataJSON, 'base64'))
    .digest();

  // Concatenate authenticatorData and clientDataHash
  const signedData = Buffer.concat([authDataBuffer, clientDataHash]);

  // Convert signature from base64 to buffer
  const signatureBuffer = Buffer.from(signature, 'base64');

  // Verify the signature
  const verified = crypto.verify(
    'sha256',
    signedData,
    publicKeyDer,
    signatureBuffer
  );

  return verified;
};

// Function to verify P-256 coordinates
export const verifyP256Point = (x, y) => {
  // P-256 curve parameters
  const p = BigInt(
    '0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'
  ); // Prime modulus
  const a = BigInt(
    '0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC'
  ); // Curve coefficient a
  const b = BigInt(
    '0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B'
  ); // Curve coefficient b

  // Convert base64url to BigInt
  const xBuf = Buffer.from(x, 'base64url');
  const yBuf = Buffer.from(y, 'base64url');

  // Check lengths
  console.log('X length in bytes:', xBuf.length); // Should be 32
  console.log('Y length in bytes:', yBuf.length); // Should be 32

  if (xBuf.length !== 32 || yBuf.length !== 32) {
    console.log('Invalid coordinate length');
    return false;
  }

  // Convert to BigInt
  const xInt = BigInt('0x' + xBuf.toString('hex'));
  const yInt = BigInt('0x' + yBuf.toString('hex'));

  // Print values for verification
  console.log('X:', xInt.toString(16));
  console.log('Y:', yInt.toString(16));

  // Check coordinates are within field
  if (xInt >= p || yInt >= p) {
    console.log('Coordinates too large');
    return false;
  }

  // Verify point satisfies curve equation: y² = x³ + ax + b (mod p)
  const left = (yInt * yInt) % p;
  const right = (xInt * xInt * xInt + a * xInt + b) % p;

  console.log('Left side of equation:', left.toString(16));
  console.log('Right side of equation:', right.toString(16));

  return left === right;
};
