import { parsePublicKeyHex, parsePayloadHex, parseSignatureHex} from './utils.js'
import { credential, assertion } from './webauthn.js'
import {
  Struct,
  ZkProgram,
  Crypto,
  createForeignCurve,
  createEcdsa,
  Bool,
} from 'o1js'

// parse webauthn data
const publicKeyHex = parsePublicKeyHex(credential.response.attestationObject)
const payloadHex = parsePayloadHex(assertion.response.clientDataJSON, assertion.response.authenticatorData)
const signatureHex = parseSignatureHex(assertion.response.signature)

// init
class Secp256r1 extends createForeignCurve(Crypto.CurveParams.Secp256r1) {}
class EcdsaP256 extends createEcdsa(Secp256r1) {}

class Params extends Struct({
  publicKey: Secp256r1,
  payload: Secp256r1.Scalar,
  signature: EcdsaP256,
}) {}

export const WebAuthnP256 = ZkProgram({
  name: 'webauthn-p256',
  publicInput: Params,
  publicOutput: Bool,
  methods: {
    verifySignature: {
      privateInputs: [],
      async method(params) {
        const { publicKey, payload, signature } = params
        /*
          Use verify for a byte array of the unhashed payload.
          Use verifySignedHash for a hashed payload (parsed and supplied as scalar).
          https://github.com/o1-labs/o1js/blob/6ebbc23710f6de023fea6d83dc93c5a914c571f2/src/lib/provable/crypto/foreign-ecdsa.ts#L81-L102
        */
        const isValid = signature.verifySignedHash(payload, publicKey)
        return { publicOutput: isValid }
      },
    },
  },
})

// parse hex values
const publicKey_ = Secp256r1.fromHex(publicKeyHex)
const payload_ = Secp256r1.Scalar.from(payloadHex)
const signature_ = EcdsaP256.fromHex(signatureHex)

// run zk program
await WebAuthnP256.compile()
const isvalid = await WebAuthnP256.verifySignature({
  publicKey: publicKey_,
  payload: payload_,
  signature: signature_,
})

console.log('signature is valid: ', isvalid.proof.publicOutput.toBoolean())