import apiClient from './client';

export interface VerifyResult {
  requestId: string;
  orgId: string;
  orgName: string;
  timestamp: string;
  ecdsaVerified: boolean;
  dilithiumVerified: boolean;
  threatFlag: boolean;
  publicKeys: {
    ecdsaPublicKey: string;
    dilithiumPublicKey: string;
    version: number;
  };
}

/** GET /verify/:requestId — public verification endpoint (unauthenticated) */
export async function verifyRequest(requestId: string): Promise<VerifyResult> {
  const { data } = await apiClient.get<VerifyResult>(`/verify/${requestId}`);
  return data;
}
