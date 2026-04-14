import { Router, Request, Response } from 'express';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import { enforceEndpointLimit } from '../../middleware/planEnforcement.js';
import {
  create,
  deleteEndpoint,
  regenerateApiKey,
  list,
  NotFoundError,
  ForbiddenError,
  PaymentRequiredError,
  ValidationError,
} from './endpointService.js';
import { Endpoint } from './Endpoint.js';

export const endpointRouter = Router({ mergeParams: true });

const getIp = (req: Request): string =>
  (req.headers['x-forwarded-for'] as string) ?? req.socket.remoteAddress ?? '0.0.0.0';

function handleServiceError(err: unknown, res: Response): void {
  if (err instanceof NotFoundError) { res.status(404).json({ error: err.message }); return; }
  if (err instanceof ForbiddenError) { res.status(403).json({ error: err.message }); return; }
  if (err instanceof PaymentRequiredError) { res.status(402).json({ error: err.message }); return; }
  if (err instanceof ValidationError) { res.status(422).json({ error: err.message }); return; }
  throw err;
}

// GET /orgs/:orgId/endpoints — list endpoints (viewer+, Req 5.1)
endpointRouter.get(
  '/',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    const endpoints = await list(req.params.orgId);
    res.json(endpoints);
  }
);

// POST /orgs/:orgId/endpoints — create endpoint (admin+, Req 5.1, 5.2)
endpointRouter.post(
  '/',
  authenticate,
  requireRole('admin'),
  enforceEndpointLimit,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { name, targetUrl, ipAllowlist } = req.body as {
        name?: string;
        targetUrl?: string;
        ipAllowlist?: string[];
      };
      if (!name || !targetUrl) {
        res.status(422).json({ error: 'name and targetUrl are required' });
        return;
      }
      const result = await create(
        req.params.orgId,
        req.user!.sub,
        { name, targetUrl, ipAllowlist },
        getIp(req)
      );
      res.status(201).json(result);
    } catch (err) {
      handleServiceError(err, res);
    }
  }
);

// GET /orgs/:orgId/endpoints/:endpointId — get single endpoint (viewer+)
endpointRouter.get(
  '/:endpointId',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    const endpoint = await Endpoint.findOne({
      _id: req.params.endpointId,
      orgId: req.params.orgId,
      isActive: true,
    }).lean();
    if (!endpoint) {
      res.status(404).json({ error: 'Endpoint not found' });
      return;
    }
    res.json(endpoint);
  }
);

// PATCH /orgs/:orgId/endpoints/:endpointId — update endpoint (admin+)
endpointRouter.patch(
  '/:endpointId',
  authenticate,
  requireRole('admin'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { name, ipAllowlist } = req.body as { name?: string; ipAllowlist?: string[] };
      const endpoint = await Endpoint.findOne({
        _id: req.params.endpointId,
        orgId: req.params.orgId,
        isActive: true,
      });
      if (!endpoint) {
        res.status(404).json({ error: 'Endpoint not found' });
        return;
      }
      if (name !== undefined) endpoint.name = name;
      if (ipAllowlist !== undefined) endpoint.ipAllowlist = ipAllowlist;
      await endpoint.save();
      res.json(endpoint);
    } catch (err) {
      handleServiceError(err, res);
    }
  }
);

// DELETE /orgs/:orgId/endpoints/:endpointId — delete endpoint (admin+, Req 5.5)
endpointRouter.delete(
  '/:endpointId',
  authenticate,
  requireRole('admin'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      await deleteEndpoint(req.params.orgId, req.params.endpointId, req.user!.sub, getIp(req));
      res.status(204).send();
    } catch (err) {
      handleServiceError(err, res);
    }
  }
);

// POST /orgs/:orgId/endpoints/:endpointId/regenerate-key — regenerate API key (admin+, Req 5.7)
endpointRouter.post(
  '/:endpointId/regenerate-key',
  authenticate,
  requireRole('admin'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const result = await regenerateApiKey(
        req.params.orgId,
        req.params.endpointId,
        req.user!.sub,
        getIp(req)
      );
      res.json(result);
    } catch (err) {
      handleServiceError(err, res);
    }
  }
);
