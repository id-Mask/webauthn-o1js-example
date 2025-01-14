// https://opotonniee.github.io/webauthn-playground/
// https://webauthn.guide/#authentication

// creation
export const publicKeyCredentialCreationOptions = {
  challenge: 'AAABeB78HrIemh1jTdJICr_3QG_RMOhp',
  rp: {
    origins: ['https://opotonniee.github.io'],
    name: 'webauthn-playground',
  },
  pubKeyCredParams: [
    {
      type: 'public-key',
      alg: -257,
    },
    {
      type: 'public-key',
      alg: -35,
    },
    {
      type: 'public-key',
      alg: -36,
    },
    {
      type: 'public-key',
      alg: -7,
    },
    {
      type: 'public-key',
      alg: -8,
    },
  ],
  excludeCredentials: [],
  timeout: 120000,
  authenticatorSelection: {
    residentKey: 'preferred',
    requireResidentKey: false,
    userVerification: 'preferred',
  },
  attestation: 'none',
  user: {
    name: 'raidas',
    displayName: 'Raidas',
    id: 'cmFpZGFz',
  },
}
  

export const credential = {
  clientExtensionResults: {
    credProps: {
      rk: true,
    },
    thalesgroup_ext_v1: {
      authenticatorDescription: {
        friendlyName: 'X Linux x_',
      },
    },
    thalesgroup_client_ext_v1: {
      clientType: 1,
    },
  },
  rawId: 'aUa_HtPHxr_JwcdWHSAweQ',
  response: {
    attestationObject:
      'o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUt8DGRTBfls-BhOH2QC404lvdhe_t2_NkvM0nQWEEADdZAAAAAOqbjWZNAR0hPOS2tIy1ddQAEGlGvx7Tx8a_ycHHVh0gMHmlAQIDJiABIVgg5O4qgyA83JJZJxUkoab83U5x5iSRU1ZVK0A4phUXm88iWCCh-pb0O2NjiTOpSldPlWnOIj_VutpQqeyHDe4SI58ftA',
    clientDataJSON:
      'eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQUFBQmVCNzhIckllbWgxalRkSklDcl8zUUdfUk1PaHAiLCJvcmlnaW4iOiJodHRwczovL29wb3Rvbm5pZWUuZ2l0aHViLmlvIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ',
    transports: ['hybrid', 'internal'],
    publicKeyAlgorithm: -7,
  },
  authenticatorAttachment: 'platform',
  id: 'aUa_HtPHxr_JwcdWHSAweQ',
  type: 'public-key',
}

// verification
export const publicKeyCredentialRequestOptions = {
  challenge: 'EGYtAMgi8B2Ey1FNVfVF93m5LEz_CfwTy00W2zoPEN4',
  timeout: 120000,
  allowCredentials: [
    {
      type: 'public-key',
      id: 'aUa_HtPHxr_JwcdWHSAweQ',
      transports: ['hybrid', 'internal'],
    },
  ],
  userVerification: 'preferred',
}

export const assertion = {
  clientExtensionResults: {},
  rawId: 'aUa_HtPHxr_JwcdWHSAweQ',
  response: {
    authenticatorData: 't8DGRTBfls-BhOH2QC404lvdhe_t2_NkvM0nQWEEADcZAAAAAA',
    signature:
      'MEYCIQCIdvFH6dV7Kgv24u_ziXi3LvJyCL3NE-NWyTFf0II5GgIhALpjUGpEGse9j7UWg_CZba5bJkddgvnBV5sSbPCBYxOv',
    userHandle: 'cmFpZGFz',
    clientDataJSON:
      'eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiRUdZdEFNZ2k4QjJFeTFGTlZmVkY5M201TEV6X0Nmd1R5MDBXMnpvUEVONCIsIm9yaWdpbiI6Imh0dHBzOi8vb3BvdG9ubmllZS5naXRodWIuaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2V9',
  },
  authenticatorAttachment: 'platform',
  id: 'aUa_HtPHxr_JwcdWHSAweQ',
  type: 'public-key',
}
