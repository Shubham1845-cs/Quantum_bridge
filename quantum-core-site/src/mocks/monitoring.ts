/**
 * Mock data for live monitoring events
 * Provides 50 sample monitoring events with various types
 */

export interface MonitoringEvent {
  _id: string;
  eventId: string;
  type: 'api_request' | 'signature_verification' | 'system_alert';
  endpoint?: string;
  method?: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  statusCode?: number;
  verificationResult?: 'verified' | 'rejected' | 'pending';
  algorithm?: 'ML-DSA-65' | 'ECDSA P-256';
  timestamp: string;
  duration?: number; // milliseconds
  requestId?: string;
  errorMessage?: string;
}

export interface SystemHealth {
  quantumBridge: number; // percentage
  mlDsa65Engine: number;
  ecdsaP256Engine: number;
  apiGateway: number;
}

// Generate monitoring events with realistic timestamps
const generateEvents = (): MonitoringEvent[] => {
  const events: MonitoringEvent[] = [];
  const now = Date.now();
  
  const eventTypes = [
    {
      type: 'api_request' as const,
      endpoint: '/api/v1/endpoints',
      method: 'GET' as const,
      statusCode: 200,
      duration: 45,
    },
    {
      type: 'signature_verification' as const,
      endpoint: '/api/v1/verify/ml-dsa',
      method: 'POST' as const,
      statusCode: 200,
      verificationResult: 'verified' as const,
      algorithm: 'ML-DSA-65' as const,
      duration: 120,
    },
    {
      type: 'signature_verification' as const,
      endpoint: '/api/v1/verify/ecdsa',
      method: 'POST' as const,
      statusCode: 200,
      verificationResult: 'verified' as const,
      algorithm: 'ECDSA P-256' as const,
      duration: 85,
    },
    {
      type: 'api_request' as const,
      endpoint: '/api/v1/keys',
      method: 'GET' as const,
      statusCode: 200,
      duration: 32,
    },
    {
      type: 'signature_verification' as const,
      endpoint: '/api/v1/verify/dual',
      method: 'POST' as const,
      statusCode: 400,
      verificationResult: 'rejected' as const,
      duration: 95,
      errorMessage: 'Invalid signature format',
    },
    {
      type: 'api_request' as const,
      endpoint: '/api/v1/endpoints/ep-001',
      method: 'PUT' as const,
      statusCode: 200,
      duration: 58,
    },
    {
      type: 'system_alert' as const,
      endpoint: '/internal/health',
      statusCode: 200,
      duration: 12,
    },
    {
      type: 'api_request' as const,
      endpoint: '/api/v1/verifications',
      method: 'GET' as const,
      statusCode: 200,
      duration: 78,
    },
    {
      type: 'signature_verification' as const,
      endpoint: '/api/v1/verify/ml-dsa',
      method: 'POST' as const,
      statusCode: 200,
      verificationResult: 'verified' as const,
      algorithm: 'ML-DSA-65' as const,
      duration: 115,
    },
    {
      type: 'api_request' as const,
      endpoint: '/api/v1/team',
      method: 'GET' as const,
      statusCode: 200,
      duration: 41,
    },
  ];

  // Generate 50 events with staggered timestamps
  for (let i = 0; i < 50; i++) {
    const template = eventTypes[i % eventTypes.length];
    const timestamp = new Date(now - (i * 30 * 1000)).toISOString(); // 30 seconds apart
    
    events.push({
      _id: `evt-${String(i + 1).padStart(3, '0')}`,
      eventId: `EVT-${5000 + i}`,
      requestId: `req-${Math.random().toString(36).substring(2, 15)}`,
      timestamp,
      ...template,
    });
  }

  return events;
};

export const mockMonitoringEvents: MonitoringEvent[] = generateEvents();

export const mockSystemHealth: SystemHealth = {
  quantumBridge: 98,
  mlDsa65Engine: 95,
  ecdsaP256Engine: 97,
  apiGateway: 99,
};

export const mockNetworkStats = {
  totalRequests: 45892,
  verified: 42103,
  rejected: 3789,
  requestsPerMinute: 156,
  averageResponseTime: 87, // milliseconds
};
