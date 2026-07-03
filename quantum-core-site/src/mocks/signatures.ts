/**
 * Mock data for cryptographic signatures
 * Provides 30 sample signature records
 */

export interface Signature {
  _id: string;
  signatureId: string; // Human-readable ID (e.g., "SIG-1234")
  algorithm: 'ML-DSA-65' | 'ECDSA P-256';
  endpointId: string;
  endpointName: string;
  publicKeyHash: string;
  privateKeyHash: string; // For reference only, never exposed
  createdAt: string;
  expiresAt: string;
  isActive: boolean;
  isRevoked: boolean;
  revokedAt?: string;
  revokedBy?: string; // User ID
  revokedReason?: string;
}

// Generate 30 signature records
const generateSignatures = (): Signature[] => {
  const signatures: Signature[] = [];
  const now = Date.now();
  
  const algorithms: Array<'ML-DSA-65' | 'ECDSA P-256'> = ['ML-DSA-65', 'ECDSA P-256'];
  
  const endpoints = [
    { id: 'ep-001', name: 'Production API' },
    { id: 'ep-002', name: 'Staging Gateway' },
    { id: 'ep-003', name: 'Development Server' },
    { id: 'ep-004', name: 'Payment Processor' },
    { id: 'ep-005', name: 'Authentication Service' },
    { id: 'ep-006', name: 'Data Pipeline' },
    { id: 'ep-007', name: 'Mobile API' },
    { id: 'ep-008', name: 'Web Dashboard' },
    { id: 'ep-009', name: 'Analytics Service' },
    { id: 'ep-010', name: 'Notification Service' },
  ];
  
  for (let i = 0; i < 30; i++) {
    const algorithm = algorithms[i % 2]; // Alternate between algorithms
    const endpoint = endpoints[i % endpoints.length];
    
    // Creation dates spread over last 180 days
    const createdAt = new Date(now - Math.random() * 180 * 24 * 60 * 60 * 1000);
    // Expiration 90 days after creation
    const expiresAt = new Date(createdAt.getTime() + 90 * 24 * 60 * 60 * 1000);
    
    // 20% chance of being revoked, 10% chance of being expired
    const isRevoked = Math.random() < 0.2;
    const isExpired = expiresAt.getTime() < now;
    const isActive = !isRevoked && !isExpired;
    
    const signature: Signature = {
      _id: `sig-${String(i + 1).padStart(3, '0')}`,
      signatureId: `SIG-${1000 + i}`,
      algorithm,
      endpointId: endpoint.id,
      endpointName: endpoint.name,
      publicKeyHash: `sha256:${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`,
      privateKeyHash: `sha256:${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`,
      createdAt: createdAt.toISOString(),
      expiresAt: expiresAt.toISOString(),
      isActive,
      isRevoked,
    };
    
    // Add revocation details if revoked
    if (isRevoked) {
      const revokedAt = new Date(createdAt.getTime() + Math.random() * 60 * 24 * 60 * 60 * 1000);
      signature.revokedAt = revokedAt.toISOString();
      signature.revokedBy = `user-${String(Math.floor(Math.random() * 3) + 1).padStart(3, '0')}`;
      
      const revokeReasons = [
        'Key compromise suspected',
        'Routine key rotation',
        'Security policy update',
        'Endpoint decommissioned',
        'Algorithm upgrade',
      ];
      signature.revokedReason = revokeReasons[Math.floor(Math.random() * revokeReasons.length)];
    }
    
    signatures.push(signature);
  }
  
  // Sort by creation date descending (newest first)
  return signatures.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
};

export const mockSignatures: Signature[] = generateSignatures();
