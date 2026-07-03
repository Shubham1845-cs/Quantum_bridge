/**
 * Mock data for signature verifications
 * Provides 100 sample verification records
 */

export interface Verification {
  _id: string;
  verificationId: string; // Human-readable ID (e.g., "VRF-2847")
  timestamp: string;
  endpoint: string;
  algorithm: 'ML-DSA-65' | 'ECDSA P-256' | 'Dual';
  result: 'verified' | 'rejected' | 'pending';
  signatureHash: string;
  publicKeyHash?: string;
  requestPayload?: Record<string, any>;
  responseTime?: number; // milliseconds
  errorDetails?: string;
  errorCode?: string;
}

export interface VerificationListResponse {
  verifications: Verification[];
  totalCount: number;
  page: number;
  pageSize: number;
}

// Generate 100 verification records
const generateVerifications = (): Verification[] => {
  const verifications: Verification[] = [];
  const now = Date.now();
  
  const endpoints = [
    '/api/v1/verify/ml-dsa',
    '/api/v1/verify/ecdsa',
    '/api/v1/verify/dual',
    '/api/v1/endpoints/ep-001/verify',
    '/api/v1/endpoints/ep-002/verify',
  ];
  
  const algorithms: Array<'ML-DSA-65' | 'ECDSA P-256' | 'Dual'> = ['ML-DSA-65', 'ECDSA P-256', 'Dual'];
  const results: Array<'verified' | 'rejected' | 'pending'> = ['verified', 'verified', 'verified', 'verified', 'rejected', 'pending'];
  
  for (let i = 0; i < 100; i++) {
    const result = results[Math.floor(Math.random() * results.length)];
    const algorithm = algorithms[Math.floor(Math.random() * algorithms.length)];
    const endpoint = endpoints[Math.floor(Math.random() * endpoints.length)];
    
    // Timestamps spread over last 7 days
    const timestamp = new Date(now - Math.random() * 7 * 24 * 60 * 60 * 1000).toISOString();
    
    const verification: Verification = {
      _id: `vrf-${String(i + 1).padStart(3, '0')}`,
      verificationId: `VRF-${3000 + i}`,
      timestamp,
      endpoint,
      algorithm,
      result,
      signatureHash: `sha256:${Math.random().toString(36).substring(2, 15)}${Math.random().toString(36).substring(2, 15)}`,
      publicKeyHash: `sha256:${Math.random().toString(36).substring(2, 15)}`,
      responseTime: Math.floor(Math.random() * 200) + 50, // 50-250ms
    };
    
    // Add error details for rejected verifications
    if (result === 'rejected') {
      const errorTypes = [
        { code: 'INVALID_SIGNATURE', message: 'Signature validation failed' },
        { code: 'EXPIRED_KEY', message: 'Public key has expired' },
        { code: 'MALFORMED_REQUEST', message: 'Request payload malformed' },
        { code: 'ALGORITHM_MISMATCH', message: 'Algorithm does not match endpoint configuration' },
      ];
      const error = errorTypes[Math.floor(Math.random() * errorTypes.length)];
      verification.errorCode = error.code;
      verification.errorDetails = error.message;
    }
    
    // Add request payload for some verifications
    if (Math.random() > 0.5) {
      verification.requestPayload = {
        message: 'Sample payload data',
        timestamp: timestamp,
      };
    }
    
    verifications.push(verification);
  }
  
  // Sort by timestamp descending (newest first)
  return verifications.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());
};

export const mockVerifications: Verification[] = generateVerifications();
