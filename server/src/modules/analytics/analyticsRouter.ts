import { Router, Request, Response } from 'express';
import { Types } from 'mongoose';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import { ProxyLog } from '../proxy/ProxyLog.js';
import { Organization } from '../organization/Organization.js';
import { PLAN_QUOTA } from '../billing/quotaService.js';
export const analyticsRouter = Router({ mergeParams: true });

/**
 * Build a Mongo timestamp filter from the query string. The frontend sends
 * `startDate`/`endDate`; older callers used `from`/`to`. Accept both so the
 * date window actually applies regardless of which name a client uses. Returns
 * undefined when neither pair is present (no date filter).
 */
function dateRangeFromQuery(req: Request): Record<string, Date> | undefined {
  const from = (req.query.startDate as string) || (req.query.from as string);
  const to = (req.query.endDate as string) || (req.query.to as string);
  if (!from && !to) return undefined;
  const range: Record<string, Date> = {};
  if (from) range.$gte = new Date(from);
  if (to) range.$lte = new Date(to);
  return range;
}

// ---------------------------------------------------------------------------
// GET /orgs/:orgId/logs
// Paginated ProxyLog query, filterable by threatFlag, date range, endpointId.
// Returns the frontend contract { logs, total, page, hasMore }.
// Requirements: 7.1, 7.4
// ---------------------------------------------------------------------------
analyticsRouter.get(
  '/',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    const { orgId } = req.params;

    const page = Math.max(1, parseInt(req.query.page as string) || 1);
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 50));
    const skip = (page - 1) * limit;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const filter: Record<string, any> = { orgId: new Types.ObjectId(orgId) };

    if (req.query.threatFlag !== undefined) {
      filter.threatFlag = req.query.threatFlag === 'true';
    }
    if (req.query.endpointId) {
      filter.endpointId = new Types.ObjectId(req.query.endpointId as string);
    }
    const timeRange = dateRangeFromQuery(req);
    if (timeRange) filter.timestamp = timeRange;

    const [logs, total] = await Promise.all([
      ProxyLog.find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).lean(),
      ProxyLog.countDocuments(filter),
    ]);

    res.json({
      logs,
      total,
      page,
      hasMore: skip + limit < total,
    });
  }
);

// ---------------------------------------------------------------------------
// GET /orgs/:orgId/logs/export
// CSV or JSON export for a selected date range.
// Requirements: 7.6
// ---------------------------------------------------------------------------
analyticsRouter.get(
  '/export',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    const { orgId } = req.params;
    const format = (req.query.format as string) === 'csv' ? 'csv' : 'json';

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const filter: Record<string, any> = { orgId: new Types.ObjectId(orgId) };
    const timeRange = dateRangeFromQuery(req);
    if (timeRange) filter.timestamp = timeRange;

    const logs = await ProxyLog.find(filter).sort({ timestamp: -1 }).lean();

    if (format === 'csv') {
      const header = 'requestId,timestamp,method,path,statusCode,latencyMs,ecdsaVerified,dilithiumVerified,threatFlag,keyVersion,forwardedToLegacy,clientIp';
      const rows = logs.map((l) =>
        [
          l.requestId,
          l.timestamp.toISOString(),
          l.method,
          l.path,
          l.statusCode,
          l.latencyMs,
          l.ecdsaVerified,
          l.dilithiumVerified,
          l.threatFlag,
          l.keyVersion,
          l.forwardedToLegacy,
          l.clientIp,
        ].join(',')
      );
      res.setHeader('Content-Type', 'text/csv');
      res.setHeader('Content-Disposition', `attachment; filename="logs-${orgId}.csv"`);
      res.send([header, ...rows].join('\n'));
    } else {
      res.setHeader('Content-Disposition', `attachment; filename="logs-${orgId}.json"`);
      res.json(logs);
    }
  }
);

// ---------------------------------------------------------------------------
// GET /orgs/:orgId/analytics/summary
// Totals for today: requests, threat flags, avg latency, plan usage. Returns
// the frontend contract AnalyticsSummary
// { requestsToday, threatsToday, avgLatency, monthlyRequestCount, quota }.
// Requirements: 7.1
// ---------------------------------------------------------------------------
analyticsRouter.get(
  '/summary',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    const { orgId } = req.params;
    const startOfDay = new Date();
    startOfDay.setUTCHours(0, 0, 0, 0);

    const [agg] = await ProxyLog.aggregate([
      {
        $match: {
          orgId: new Types.ObjectId(orgId),
          timestamp: { $gte: startOfDay },
        },
      },
      {
        $group: {
          _id: null,
          totalRequests: { $sum: 1 },
          threatFlagsToday: { $sum: { $cond: ['$threatFlag', 1, 0] } },
          avgLatencyMs: { $avg: '$latencyMs' },
        },
      },
    ]);

    // Fetch org for plan details
    const org = await Organization.findById(orgId).lean();
    const plan = org?.plan || 'free';
    const planUsed = org?.monthlyRequestCount || 0;
    const rawQuota = PLAN_QUOTA[plan] ?? 10_000;
    const planQuota = rawQuota === Infinity ? 0 : rawQuota;

    res.json({
      requestsToday: agg?.totalRequests ?? 0,
      threatsToday: agg?.threatFlagsToday ?? 0,
      avgLatency: agg ? Math.round(agg.avgLatencyMs) : 0,
      monthlyRequestCount: planUsed,
      quota: planQuota,
    });
  }
);

// ---------------------------------------------------------------------------
// GET /orgs/:orgId/analytics/timeseries
// Hourly or daily aggregation of request counts, threat flags, and signature
// verification rates. Returns a BARE TimeseriesDataPoint[] (the frontend
// contract) so charts can .map/.reduce directly — never an envelope object,
// which is what caused the "timeseries.reduce is not a function" crash.
// Requirements: 7.2
// ---------------------------------------------------------------------------
analyticsRouter.get(
  '/timeseries',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    const { orgId } = req.params;
    const granularity = (req.query.granularity as string) === 'daily' ? 'daily' : 'hourly';
    const hourly = granularity === 'hourly';

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const matchFilter: Record<string, any> = { orgId: new Types.ObjectId(orgId) };
    const timeRange = dateRangeFromQuery(req);
    if (timeRange) matchFilter.timestamp = timeRange;

    // Bucket by UTC date components; hourly adds the hour. The frontend
    // reconstructs local display time from `timestamp` itself.
    const dateGroupId = hourly
      ? {
          year: { $year: '$timestamp' },
          month: { $month: '$timestamp' },
          day: { $dayOfMonth: '$timestamp' },
          hour: { $hour: '$timestamp' },
        }
      : {
          year: { $year: '$timestamp' },
          month: { $month: '$timestamp' },
          day: { $dayOfMonth: '$timestamp' },
        };

    interface Bucket {
      _id: { year: number; month: number; day: number; hour?: number };
      requests: number;
      threatFlags: number;
      ecdsaSuccesses: number;
      dilithiumSuccesses: number;
    }

    const buckets = (await ProxyLog.aggregate([
      { $match: matchFilter },
      {
        $group: {
          _id: dateGroupId,
          requests: { $sum: 1 },
          threatFlags: { $sum: { $cond: ['$threatFlag', 1, 0] } },
          ecdsaSuccesses: { $sum: { $cond: ['$ecdsaVerified', 1, 0] } },
          dilithiumSuccesses: { $sum: { $cond: ['$dilithiumVerified', 1, 0] } },
        },
      },
    ])) as unknown as Bucket[];

    const series = buckets
      .map((b) => {
        const { year, month, day, hour } = b._id;
        const timestamp = new Date(Date.UTC(year, month - 1, day, hour ?? 0)).toISOString();
        const reqs = b.requests ?? 0;
        return {
          timestamp,
          requestCount: reqs,
          ecdsaVerificationRate: reqs > 0 ? b.ecdsaSuccesses / reqs : 0,
          dilithiumVerificationRate: reqs > 0 ? b.dilithiumSuccesses / reqs : 0,
          threatFlagRate: reqs > 0 ? b.threatFlags / reqs : 0,
        };
      })
      .sort((a, b) => a.timestamp.localeCompare(b.timestamp));

    res.json(series);
  }
);
