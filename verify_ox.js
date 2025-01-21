import { parsePublicKeyHex, parsePayloadHex, parseSignatureHex} from './utils.js'
import { credential, assertion } from './webauthn.js'
import * as ox from 'ox'

// parse webauthn data
const publicKeyHex = parsePublicKeyHex(credential.response.attestationObject)
const payloadHex = parsePayloadHex(assertion.response.clientDataJSON, assertion.response.authenticatorData)
const signatureHex = parseSignatureHex(assertion.response.signature)

// verify in ox
const isValid = ox.P256.verify({
  hash: false,
  publicKey: ox.PublicKey.fromHex(publicKeyHex),
  payload: ox.Bytes.fromHex(payloadHex),
  signature: ox.Signature.fromHex(signatureHex),
})

console.log('signature is valid:', isValid)
