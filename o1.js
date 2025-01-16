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
import { credential, assertion } from './webauthnData.js';


export class Bytes32 extends Bytes(32) {}
export class Secp256r1 extends createForeignCurve(Crypto.CurveParams.Secp256r1) {}
export class EcdsaP256 extends createEcdsa(Secp256r1) {}

export class VerifyParams extends Struct({
  payload: Bytes32,
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

const payload = undefined
const publicKey = undefined
const signature = undefined

await WebAuthnP256.compile()
const valid = await WebAuthnP256.verifySignature({
  payload: Bytes32.fromHex(payload),
  publicKey: Secp256r1.fromHex(publicKey),
  signature: EcdsaP256.fromHex(signature),
})

console.log('O1 P256 valid', valid.proof.publicOutput.toBoolean());