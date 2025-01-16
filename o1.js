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
  publicKey: Secp256r1,
  payload: Bytes32,
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
        const { publicKey, payload, signature } = params;
        return {
          publicOutput: signature.verify(payload, publicKey),
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
const payload = '347f1c29e0552da6f5201cc93952c39bc45b4947ea9b3f2c7cb08df8c806e516'
const signature = '0x8876f147e9d57b2a0bf6e2eff38978b72ef27208bdcd13e356c9315fd082391aba63506a441ac7bd8fb51683f0996dae5b26475d82f9c1579b126cf0816313af'

// testing
const isValidHex = (hex) => /^0x[0-9a-fA-F]+$/.test(hex);

console.log('Public key valid hex?', isValidHex(publicKey));
console.log('Payload valid hex?', isValidHex(payload));
console.log('Signature valid hex?', isValidHex(signature));

// Also log their lengths
console.log('Public key length:', publicKey.length);
console.log('Payload length:', payload.length);
console.log('Signature length:', signature.length);

try {
  console.log('Testing public key:', BigInt(publicKey));
} catch (e) {
  console.log('Public key conversion failed:', e.message);
}

try {
  console.log('Testing payload:', BigInt(payload));
} catch (e) {
  console.log('Payload conversion failed:', e.message);
}

try {
  console.log('Testing signature:', BigInt(signature));
} catch (e) {
  console.log('Signature conversion failed:', e.message);
}

// verify
const publicKey_ = Secp256r1.fromHex(publicKey)
const payload_ = Bytes32.fromHex(payload)
const signature_ = EcdsaP256.fromHex(signature)

console.log(payload_, publicKey_, signature_)

await WebAuthnP256.compile()
const valid = await WebAuthnP256.verifySignature({
  publicKey: publicKey_,
  payload: payload_,
  signature: signature_,
})

console.log('O1 P256 valid', valid.proof.publicOutput.toBoolean());