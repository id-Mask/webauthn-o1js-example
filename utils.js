import cbor from 'cbor'
import { Buffer } from 'buffer'
import * as crypto from 'crypto'


/*
  Parse public key from credentials.response.attestationObject
  It also holds AAGUID and CredId (which can be used to automatically use key of this ID)
  but these are not parsed here
*/
export const parseAttestationObject = (attestationObject) => {
  // First decode the base64 to get the raw bytes
  const attestationBuffer = Buffer.from(attestationObject, 'base64')

  // Decode the CBOR
  const attestationCbor = cbor.decodeFirstSync(attestationBuffer)

  // Get the authData from the attestation
  const { authData } = attestationCbor

  // The public key starts after:
  // 32 bytes of RP ID hash
  // 1 byte of flags
  // 4 bytes of signature counter
  // 16 bytes of AAGUID
  // 2 bytes of credential ID length (L)
  // L bytes of credential ID
  let position = 32 + 1 + 4

  // Skip AAGUID
  position += 16

  // Get credential ID length
  const credentialIdLength = (authData[position] << 8) | authData[position + 1]
  position += 2

  // Skip credential ID
  position += credentialIdLength

  // The rest is the CBOR-encoded public key
  const publicKeyCose = authData.slice(position)
  const publicKeyObject = cbor.decodeFirstSync(publicKeyCose)

  // COSE key to JWK conversion
  // For ES256 (ECDSA with P-256 curve)
  const x = publicKeyObject.get(-2) // X coordinate
  const y = publicKeyObject.get(-3) // Y coordinate

  return {
    kty: 'EC',
    crv: 'P-256',
    x: Buffer.from(x).toString('base64url'),
    y: Buffer.from(y).toString('base64url'),
    ext: true,
  }
}

/*
  Parse the public key stored inside the attestationObject of credential:
    - parse attesttion object from the inside of the credentials response (encoded as base64)
    - parse both x and y as buffer and make sure both are 32 bytes
    - convert it to to uncompressed point hex
*/
export const parsePublicKeyHex = (attestationObject) => {
  // parse points
  const pk = parseAttestationObject(attestationObject)
  const xBuffer = Buffer.from(pk.x, 'base64')
  const yBuffer = Buffer.from(pk.y, 'base64')

  // ensure both x and y are 32 bytes as expected for P-256
  if (xBuffer.length !== 32 || yBuffer.length !== 32) {
    throw new Error('Invalid x or y length for P-256 curve.')
  }

  // create the uncompressed point buffer
  const uncompressedPoint = Buffer.concat([Buffer.from([0x04]), xBuffer, yBuffer])
  const uncompressedPointHex = uncompressedPoint.toString('hex')
  const publicKeyHex = '0x' + uncompressedPointHex

  return publicKeyHex
}

/*
  Read the signed payload into hex payload = hash(concat(authenticatorData, hashedClientDataJSON)):
*/
export const parsePayloadHex = (clientDataJSON, authenticatorData) => {
  const clientDataJSONBuffer = Buffer.from(clientDataJSON, 'base64')
  const hashedClientDataJSON = crypto.createHash('sha256').update(clientDataJSONBuffer).digest()
  const authenticatorDataBuffer = Buffer.from(authenticatorData, 'base64')

  const payload = Buffer.concat([authenticatorDataBuffer, hashedClientDataJSON])
  const hashedPayload = crypto.createHash('sha256').update(payload).digest()
  const payloadHex = '0x' + hashedPayload.toString('hex')

  return payloadHex
}

/*
  Parse signature stored inside the assertion response:
    - read the signature as asn.1 sequence
    - convert asn.1 to ecdsa signature form
*/
export const parseSignatureHex = (signature) => {

  const readAsn1IntegerSequence = (input) => {
    if (input[0] !== 0x30) throw new Error('Input is not an ASN.1 sequence')
    const seqLength = input[1]
    const elements = []
  
  
    let current = input.slice(2, 2 + seqLength)
    while (current.length > 0) {
      const tag = current[0]
      if (tag !== 0x02) throw new Error('Expected ASN.1 sequence element to be an INTEGER')
  
  
      const elLength = current[1]
      elements.push(current.slice(2, 2 + elLength))
  
  
      current = current.slice(2 + elLength)
    }
    return elements
  }
  
  const convertEcdsaAsn1Signature = (input) => {
    const elements = readAsn1IntegerSequence(input)
    if (elements.length !== 2) throw new Error('Expected 2 ASN.1 sequence elements')
    let [r, s] = elements
    
    // Each component should be 32 bytes for P-256
    const targetLength = 32
    
    // Handle leading zeros properly
    r = r[0] === 0 ? r.slice(1) : r
    s = s[0] === 0 ? s.slice(1) : s
    
    // Pad if shorter than 32 bytes
    if (r.length < targetLength) {
      r = Buffer.concat([Buffer.alloc(targetLength - r.length, 0), r])
    }
    if (s.length < targetLength) {
      s = Buffer.concat([Buffer.alloc(targetLength - s.length, 0), s])
    }
    
    // Verify final lengths
    if (r.length !== targetLength || s.length !== targetLength) {
      throw new Error(`Invalid R or S length. Expected ${targetLength} bytes each`)
    }
    
    return Buffer.concat([r, s])
  }
  
  const signature_ = convertEcdsaAsn1Signature(
    new Uint8Array(
      Buffer.from(signature, 'base64')
    )
  )
  const signatureHex = '0x' + signature_.toString('hex')

  return signatureHex
}

/*
  verify P-256 coordinates
*/
export const verifyP256Point = (x, y) => {
  // P-256 curve parameters
  const p = BigInt(
    '0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF'
  ) // Prime modulus
  const a = BigInt(
    '0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC'
  ) // Curve coefficient a
  const b = BigInt(
    '0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B'
  ) // Curve coefficient b

  // Convert base64url to BigInt
  const xBuf = Buffer.from(x, 'base64url')
  const yBuf = Buffer.from(y, 'base64url')

  // Check lengths
  console.log('X length in bytes:', xBuf.length) // Should be 32
  console.log('Y length in bytes:', yBuf.length) // Should be 32

  if (xBuf.length !== 32 || yBuf.length !== 32) {
    console.log('Invalid coordinate length')
    return false
  }

  // Convert to BigInt
  const xInt = BigInt('0x' + xBuf.toString('hex'))
  const yInt = BigInt('0x' + yBuf.toString('hex'))

  // Print values for verification
  console.log('X:', xInt.toString(16))
  console.log('Y:', yInt.toString(16))

  // Check coordinates are within field
  if (xInt >= p || yInt >= p) {
    console.log('Coordinates too large')
    return false
  }

  // Verify point satisfies curve equation: y² = x³ + ax + b (mod p)
  const left = (yInt * yInt) % p
  const right = (xInt * xInt * xInt + a * xInt + b) % p

  console.log('Left side of equation:', left.toString(16))
  console.log('Right side of equation:', right.toString(16))

  return left === right
}

