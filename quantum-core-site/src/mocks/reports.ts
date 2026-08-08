/**
 * Mock data for security reports
 * Provides 10 sample report records
 */

export interface Report {
  _id: string;
  reportId: string; // Human-readable ID (e.g., "RPT-5829")
  type: 'security_summary' | 'verification_audit' | 'threat_analysis' | 'system_health';
  title: string;
  generatedAt: string;
  generatedBy: string; // User ID
  dateRange: {
    start: string;
    end: string;
  };
  summary: string;
  sections: ReportSection[];
  metadata: {
    totalAlerts?: number;
    totalVerifications?: number;
    totalEndpoints?: number;
    averageResponseTime?: number;
    [key: string]: any;
  };
}

export interface ReportSection {
  title: string;
  content: string;
  data?: any[];
  charts?: {
    type: 'line' | 'bar' | 'pie' | 'area';
    data: any[];
    config: Record<string, any>;
  }[];
}

export interface ReportHistoryItem {
  _id: string;
  reportId: string;
  type: string;
  generatedAt: string;
  fileSize: number; // bytes
}

const now = Date.now();

export const mockReports: Report[] = [
  {
    _id: 'rpt-001',
    reportId: 'RPT-5829',
    type: 'security_summary',
    title: 'Security Summary - June 2024',
    generatedAt: new Date(now - 2 * 24 * 60 * 60 * 1000).toISOString(),
    generatedBy: 'user-001',
    dateRange: {
      start: '2024-06-01T00:00:00Z',
      end: '2024-06-30T23:59:59Z',
    },
    summary: 'Comprehensive security overview for June 2024, including 42,103 successful verifications, 3,789 rejected signatures, and 28 security alerts resolved.',
    sections: [
      {
        title: 'Executive Summary',
        content: 'This month showed strong security posture with a 91.7% verification success rate. Critical alerts were addressed within an average of 2.3 hours.',
      },
      {
        title: 'Verification Statistics',
        content: 'Total verifications: 45,892. ML-DSA-65: 28,451 (62%), ECDSA P-256: 17,441 (38%).',
        data: [
          { algorithm: 'ML-DSA-65', count: 28451, successRate: 93.2 },
          { algorithm: 'ECDSA P-256', count: 17441, successRate: 89.4 },
        ],
      },
      {
        title: 'Security Alerts',
        content: '28 alerts generated this month: 5 critical, 12 high, 8 medium, 3 low priority.',
      },
    ],
    metadata: {
      totalAlerts: 28,
      totalVerifications: 45892,
      totalEndpoints: 15,
      averageResponseTime: 87,
    },
  },
  {
    _id: 'rpt-002',
    reportId: 'RPT-5828',
    type: 'verification_audit',
    title: 'Verification Audit - Q2 2024',
    generatedAt: new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString(),
    generatedBy: 'user-002',
    dateRange: {
      start: '2024-04-01T00:00:00Z',
      end: '2024-06-30T23:59:59Z',
    },
    summary: 'Quarterly verification audit covering 137,453 signature verification requests across all endpoints.',
    sections: [
      {
        title: 'Audit Overview',
        content: 'Comprehensive review of all verification requests in Q2 2024, with detailed analysis of success and failure patterns.',
      },
      {
        title: 'Failure Analysis',
        content: 'Primary failure causes: Invalid signature format (42%), Expired keys (28%), Algorithm mismatch (18%), Other (12%).',
      },
      {
        title: 'Compliance Status',
        content: 'All verifications logged and retained per compliance requirements. No data retention policy violations detected.',
      },
    ],
    metadata: {
      totalVerifications: 137453,
      successfulVerifications: 125891,
      rejectedVerifications: 11562,
      successRate: 91.6,
    },
  },
  {
    _id: 'rpt-003',
    reportId: 'RPT-5827',
    type: 'threat_analysis',
    title: 'Threat Analysis - May 2024',
    generatedAt: new Date(now - 14 * 24 * 60 * 60 * 1000).toISOString(),
    generatedBy: 'user-001',
    dateRange: {
      start: '2024-05-01T00:00:00Z',
      end: '2024-05-31T23:59:59Z',
    },
    summary: 'Monthly threat analysis identifying 3 high-priority security incidents and 12 potential vulnerabilities.',
    sections: [
      {
        title: 'Threat Landscape',
        content: 'Detected 15 unauthorized access attempts, all successfully blocked by security policies.',
      },
      {
        title: 'Incident Response',
        content: '3 incidents escalated to security team. Average response time: 1.8 hours. All incidents resolved within 24 hours.',
      },
      {
        title: 'Recommendations',
        content: 'Implement stricter rate limiting, enhance IP allowlist monitoring, enable multi-factor authentication for admin endpoints.',
      },
    ],
    metadata: {
      totalIncidents: 15,
      criticalIncidents: 3,
      resolvedIncidents: 15,
      averageResolutionTime: 4.2,
    },
  },
  {
    _id: 'rpt-004',
    reportId: 'RPT-5826',
    type: 'system_health',
    title: 'System Health Report - Week 22',
    generatedAt: new Date(now - 21 * 24 * 60 * 60 * 1000).toISOString(),
    generatedBy: 'user-003',
    dateRange: {
      start: '2024-05-27T00:00:00Z',
      end: '2024-06-02T23:59:59Z',
    },
    summary: 'Weekly system health metrics showing 99.8% uptime and optimal performance across all services.',
    sections: [
      {
        title: 'Uptime and Availability',
        content: 'Quantum Bridge: 99.9%, ML-DSA-65 Engine: 99.7%, ECDSA P-256 Engine: 99.8%, API Gateway: 99.9%.',
      },
      {
        title: 'Performance Metrics',
        content: 'Average response time: 82ms. Peak load: 1,850 requests/minute. Memory utilization: 68% average.',
      },
      {
        title: 'Resource Utilization',
        content: 'CPU: 45% average, Memory: 68% average, Disk: 62% utilization, Network: 1.2 Gbps average throughput.',
      },
    ],
    metadata: {
      uptime: 99.8,
      averageResponseTime: 82,
      peakLoad: 1850,
      totalRequests: 186420,
    },
  },
  {
    _id: 'rpt-005',
    reportId: 'RPT-5825',
    type: 'security_summary',
    title: 'Security Summary - May 2024',
    generatedAt: new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString(),
    generatedBy: 'user-001',
    dateRange: {
      start: '2024-05-01T00:00:00Z',
      end: '2024-05-31T23:59:59Z',
    },
    summary: 'May 2024 security overview highlighting improved verification success rate and reduced alert response times.',
    sections: [
      {
        title: 'Executive Summary',
        content: 'Verification success rate improved to 92.3%, up from 90.8% in April. Average alert resolution time reduced by 18%.',
      },
      {
        title: 'Key Metrics',
        content: 'Total verifications: 43,251. Successful: 39,923 (92.3%). Rejected: 3,328 (7.7%).',
      },
    ],
    metadata: {
      totalAlerts: 24,
      totalVerifications: 43251,
      successRate: 92.3,
    },
  },
  {
    _id: 'rpt-006',
    reportId: 'RPT-5824',
    type: 'verification_audit',
    title: 'Verification Audit - May 2024',
    generatedAt: new Date(now - 35 * 24 * 60 * 60 * 1000).toISOString(),
    generatedBy: 'user-002',
    dateRange: {
      start: '2024-05-01T00:00:00Z',
      end: '2024-05-31T23:59:59Z',
    },
    summary: 'Detailed verification audit for May 2024 compliance reporting.',
    sections: [
      {
        title: 'Audit Findings',
        content: 'All verification requests properly logged. No compliance violations detected.',
      },
    ],
    metadata: {
      totalVerifications: 43251,
      auditCompliant: true,
    },
  },
  {
    _id: 'rpt-007',
    reportId: 'RPT-5823',
    type: 'threat_analysis',
    title: 'Threat Analysis - Q1 2024',
    generatedAt: new Date(now - 60 * 24 * 60 * 60 * 1000).toISOString(),
    generatedBy: 'user-001',
    dateRange: {
      start: '2024-01-01T00:00:00Z',
      end: '2024-03-31T23:59:59Z',
    },
    summary: 'Quarterly threat analysis identifying emerging attack patterns and mitigation strategies.',
    sections: [
      {
        title: 'Threat Overview',
        content: 'Detected 42 security incidents across Q1. 38 successfully mitigated, 4 required manual intervention.',
      },
      {
        title: 'Attack Patterns',
        content: 'Primary attack vectors: Signature replay (35%), Key compromise attempts (28%), Brute force (22%), Other (15%).',
      },
    ],
    metadata: {
      totalIncidents: 42,
      mitigatedIncidents: 38,
      manualInterventions: 4,
    },
  },
  {
    _id: 'rpt-008',
    reportId: 'RPT-5822',
    type: 'system_health',
    title: 'System Health Report - April 2024',
    generatedAt: new Date(now - 75 * 24 * 60 * 60 * 1000).toISOString(),
    generatedBy: 'user-003',
    dateRange: {
      start: '2024-04-01T00:00:00Z',
      end: '2024-04-30T23:59:59Z',
    },
    summary: 'April system health report showing stable performance with minor optimization opportunities.',
    sections: [
      {
        title: 'Performance Analysis',
        content: 'Average response time: 89ms. 99.7% uptime maintained across all services.',
      },
    ],
    metadata: {
      uptime: 99.7,
      averageResponseTime: 89,
    },
  },
  {
    _id: 'rpt-009',
    reportId: 'RPT-5821',
    type: 'security_summary',
    title: 'Security Summary - April 2024',
    generatedAt: new Date(now - 90 * 24 * 60 * 60 * 1000).toISOString(),
    generatedBy: 'user-001',
    dateRange: {
      start: '2024-04-01T00:00:00Z',
      end: '2024-04-30T23:59:59Z',
    },
    summary: 'April 2024 security summary with focus on signature algorithm migration.',
    sections: [
      {
        title: 'Migration Progress',
        content: 'ML-DSA-65 adoption increased to 58% of all verifications, up from 42% in March.',
      },
    ],
    metadata: {
      totalVerifications: 41892,
      mlDsaPercentage: 58,
    },
  },
  {
    _id: 'rpt-010',
    reportId: 'RPT-5820',
    type: 'verification_audit',
    title: 'Verification Audit - Q1 2024',
    generatedAt: new Date(now - 95 * 24 * 60 * 60 * 1000).toISOString(),
    generatedBy: 'user-002',
    dateRange: {
      start: '2024-01-01T00:00:00Z',
      end: '2024-03-31T23:59:59Z',
    },
    summary: 'Q1 2024 verification audit for annual compliance reporting.',
    sections: [
      {
        title: 'Quarterly Summary',
        content: '124,582 verifications processed. 90.8% success rate maintained.',
      },
    ],
    metadata: {
      totalVerifications: 124582,
      successRate: 90.8,
    },
  },
];

export const mockReportHistory: ReportHistoryItem[] = mockReports.map((report) => ({
  _id: report._id,
  reportId: report.reportId,
  type: report.type,
  generatedAt: report.generatedAt,
  fileSize: Math.floor(Math.random() * 500000) + 100000, // 100KB - 600KB
}));
