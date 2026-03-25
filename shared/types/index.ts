// Shared TypeScript interfaces for QuantumBridge
// Populated as modules are implemented

export type Plan = 'free' | 'pro' | 'enterprise';

export type OrgRole = 'owner' | 'admin' | 'viewer';

export type MemberStatus = 'active' | 'pending';

export interface DualSignature {
  ecdsaSignature: string;    // base64
  dilithiumSignature: string; // base64
  keyVersion: number;
}

export interface VerifyResult {
  ecdsaVerified: boolean;
  dilithiumVerified: boolean;
  threatFlag: boolean;
}

export interface PublicKeySet {
  ecdsaPublicKey: string;    // PEM
  dilithiumPublicKey: string; // base64
  version: number;
}
