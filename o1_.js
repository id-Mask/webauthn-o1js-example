// https://github.com/o1-labs/o1js/blob/996ebb3119ec087a0badc16ea8036766cb68d3fb/src/lib/provable/test/ecdsa.unit-test.ts#L36-L75
// https://github.com/o1-labs/o1js/blob/996ebb3119ec087a0badc16ea8036766cb68d3fb/src/lib/provable/test/ecdsa.unit-test.ts#L274


/*
  Verify method might be accepting bytes array of un-hashed message.
  https://github.com/o1-labs/o1js/blob/6ebbc23710f6de023fea6d83dc93c5a914c571f2/src/lib/provable/crypto/foreign-ecdsa.ts#L81-L102

  But there's this verifySignedHash method, Just not sure why it fails to parse my bigints :/ I think this is something to try out.
*/

import {
  Struct,
  ZkProgram,
  Crypto,
  createForeignCurve,
  createEcdsa,
  Bool,
  Bytes,
  Provable,
  Field,
} from 'o1js';


export class Bytes32 extends Bytes(32) {}
export class Secp256r1 extends createForeignCurve(Crypto.CurveParams.Secp256r1) {}
export class Secp256k1Scalar extends Secp256r1.Scalar {}
export class EcdsaP256 extends createEcdsa(Secp256r1) {}

export class Params extends Struct({
  publicKey: Secp256r1,
  payload: Secp256k1Scalar,
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
        const { publicKey, payload, signature } = params;
        return {
          publicOutput: signature.verifySignedHash(payload, publicKey),
        };
      },
    },
  },
});

// it works if I remove 0x from payload and publicKey ??
// https://docs.minaprotocol.com/zkapps/o1js-reference/classes/ForeignCurve#example-5
// https://docs.minaprotocol.com/zkapps/o1js-reference/functions/Bytes
// https://docs.minaprotocol.com/zkapps/o1js-reference/classes/EcdsaSignature#fromhex
const publicKey = '04e4ee2a83203cdc9259271524a1a6fcdd4e71e624915356552b4038a615179bcfa1fa96f43b63638933a94a574f9569ce223fd5bada50a9ec870dee12239f1fb4'
const payload = '0x347f1c29e0552da6f5201cc93952c39bc45b4947ea9b3f2c7cb08df8c806e516'
const signature = '0x8876f147e9d57b2a0bf6e2eff38978b72ef27208bdcd13e356c9315fd082391aba63506a441ac7bd8fb51683f0996dae5b26475d82f9c1579b126cf0816313af'

// testing
const isValidHex = (hex) => /^0x[0-9a-fA-F]+$/.test(hex);

console.log(
  'Is valid hex? ', 
  isValidHex(publicKey),
  isValidHex(payload),
  isValidHex(signature),
);

// Also log their lengths
console.log(
  'Bytes length. Public key, Payload, Signature', 
  publicKey.length,
  payload.length,
  signature.length
);

// verify
const publicKey_ = Secp256r1.fromHex(publicKey).toBigint()
const payload_ = Secp256k1Scalar.from(payload)
const signature_ = EcdsaP256.fromHex(signature)

console.log(payload_, publicKey_, signature_)

let pk = Provable.witness(Secp256r1, () => publicKey_);
let msg = Provable.witness(Secp256k1Scalar, () => payload_);
let sig = Provable.witness(EcdsaP256, () => signature_);

let isValid = sig.verifySignedHash(msg, pk);
console.log(isValid.toBoolean())

console.log(msg, pk, sig)

// verify inside zkProgram
await WebAuthnP256.compile()
const valid = await WebAuthnP256.verifySignature({
  publicKey: publicKey_,
  payload: payload_,
  signature: signature_,
})

console.log('O1 P256 valid', valid.proof.publicOutput.toBoolean());