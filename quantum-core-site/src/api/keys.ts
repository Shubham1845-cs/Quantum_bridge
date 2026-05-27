import apiClient from './client';

export interface PublicKeySet {
  ecdsaPublicKey: string;
  dilithiumPublicKey: string;
  version: number;
}

export interface KeyVaultRecord {
  version: number;
  ecdsaPublicKey: string;
  dilithiumPublicKey: string;
  isActive: boolean;
  expiresAt: string;
  graceExpiresAt?: string;
  createdAt: string;
}

/** GET /orgs/:orgId/keys — get all key versions for an organization */
export async function getKeys(orgId: string): Promise<KeyVaultRecord[]> {
  const { data } = await apiClient.get<KeyVaultRecord[]>(`/orgs/${orgId}/keys`);
  return data;
}

/** POST /orgs/:orgId/keys/rotate — manually rotate keys */
export async function rotateKeys(orgId: string): Promise<void> {
  await apiClient.post(`/orgs/${orgId}/keys/rotate`);
}
