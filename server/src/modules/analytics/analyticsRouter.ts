import { Router, Request, Response } from 'express';
import { Types } from 'mongoose';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import { ProxyLog } from '../proxy/ProxyLog.js';

export const analyticsRouter = Router({ mergeParams: true });

// ---------------------------------------------------------------------------
// GET /orgs/:orgId/logs
// Paginated ProxyLog query, filterable by threatFlag, date range, endpointId.
// Requirements: 7.1, 7.4
// ---------------------------------------------------------------------------
analyticsRouter.get(
  '/',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    const { orgId } = req.params;

    const page   = Math.max(1, parseInt(req.query.page   as string) || 1);
    const limit  = Math.min(100, Math.max(1, parseInt(req.query.limit as string) || 50));
    const skip   = (page - 1) * limit;

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const filter: Record<string, any> = { orgId: new Types.ObjectId(orgId) };

    if (req.query.threatFlag !== undefined) {
      filter.threatFlag = req.query.threatFlag === 'true';
    }
    if (req.query.endpointId) {
      filter.endpointId = new Types.ObjectId(req.query.endpointId as string);
    }
    if (req.query.from || req.query.to) {
      filter.timestamp = {};
      if (req.query.from) filter.timestamp.$gte = new Date(req.query.from as string);
      if (req.query.to)   filter.timestamp.$lte = new Date(req.query.to   as string);
    }

    const [logs, total] = await Promise.all([
      ProxyLog.find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).lean(),
      ProxyLog.countDocuments(filter),
    ]);

    res.json({
      data: logs,
      pagination: { page, limit, total, pages: Math.ceil(total / limit) },
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
    if (req.query.from || req.query.to) {
      filter.timestamp = {};
      if (req.query.from) filter.timestamp.$gte = new Date(req.query.from as string);
      if (req.query.to)   filter.timestamp.$lte = new Date(req.query.to   as string);
    }

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
// Totals for today: requests, threat flags, avg latency, sig success rate.
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
          totalRequests:    { $sum: 1 },
          threatFlagsToday: { $sum: { $cond: ['$threatFlag', 1, 0] } },
          avgLatencyMs:     { $avg: '$latencyMs' },
          ecdsaSuccesses:   { $sum: { $cond: ['$ecdsaVerified', 1, 0] } },
          dilithiumSuccesses: { $sum: { $cond: ['$dilithiumVerified', 1, 0] } },
        },
      },
    ]);

    const total = agg?.totalRequests ?? 0;
    res.json({
      totalRequestsToday:   total,
      threatFlagsToday:     agg?.threatFlagsToday ?? 0,
      avgLatencyMs:         agg ? Math.round(agg.avgLatencyMs) : 0,
      ecdsaSuccessRate:     total > 0 ? agg.ecdsaSuccesses / total : 0,
      dilithiumSuccessRate: total > 0 ? agg.dilithiumSuccesses / total : 0,
    });
  }
);

// ---------------------------------------------------------------------------
// GET /orgs/:orgId/analytics/timeseries
// Hourly or daily aggregation of request counts and threat flags.
// Requirements: 7.2
// ---------------------------------------------------------------------------
analyticsRouter.get(
  '/timeseries',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    const { orgId } = req.params;
    const granularity = (req.query.granularity as string) === 'daily' ? 'daily' : 'hourly';

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const matchFilter: Record<string, any> = { orgId: new Types.ObjectId(orgId) };
    if (req.query.from || req.query.to) {
      matchFilter.timestamp = {};
      if (req.query.from) matchFilter.timestamp.$gte = new Date(req.query.from as string);
      if (req.query.to)   matchFilter.timestamp.$lte = new Date(req.query.to   as string);
    }

    const dateGroupId =
      granularity === 'daily'
        ? {
            year:  { $year: '$timestamp' },
            month: { $month: '$timestamp' },
            day:   { $dayOfMonth: '$timestamp' },
          }
        : {
            year:  { $year: '$timestamp' },
            month: { $month: '$timestamp' },
            day:   { $dayOfMonth: '$timestamp' },
            hour:  { $hour: '$timestamp' },
          };

    const buckets = await ProxyLog.aggregate([
      { $match: matchFilter },
      {
        $group: {
          _id:          dateGroupId,
          requests:     { $sum: 1 },
          threatFlags:  { $sum: { $cond: ['$threatFlag', 1, 0] } },
          avgLatencyMs: { $avg: '$latencyMs' },
        },
      },
      { $sort: { '_id.year': 1, '_id.month': 1, '_id.day': 1, '_id.hour': 1 } },
    ]);

    res.json({ granularity, data: buckets });
  }
);
