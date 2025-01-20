import {
  Struct,
  ZkProgram,
  Crypto,
  createForeignCurve,
  createEcdsa,
  Bool,
} from 'o1js'


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

// input values in hex
const publicKey = '0x04e4ee2a83203cdc9259271524a1a6fcdd4e71e624915356552b4038a615179bcfa1fa96f43b63638933a94a574f9569ce223fd5bada50a9ec870dee12239f1fb4'
const payload = '0x347f1c29e0552da6f5201cc93952c39bc45b4947ea9b3f2c7cb08df8c806e516'
const signature = '0x8876f147e9d57b2a0bf6e2eff38978b72ef27208bdcd13e356c9315fd082391aba63506a441ac7bd8fb51683f0996dae5b26475d82f9c1579b126cf0816313af'

// parse hex values
const publicKey_ = Secp256r1.fromHex(publicKey)
const payload_ = Secp256r1.Scalar.from(payload)
const signature_ = EcdsaP256.fromHex(signature)

// run zk program
await WebAuthnP256.compile()
const valid = await WebAuthnP256.verifySignature({
  publicKey: publicKey_,
  payload: payload_,
  signature: signature_,
})

console.log(valid.proof.publicOutput.toBoolean())