import { Router, Request, Response } from 'express';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import { register, getDeliveryLog, WebhookError } from './webhookService.js';
import { WebhookConfig } from './WebhookConfig.js';
import { writeAuditLog } from '../../utils/auditLog.js';
import { Types } from 'mongoose';

export const webhookRouter = Router({ mergeParams: true });

// ---------------------------------------------------------------------------
// GET /orgs/:orgId/webhooks — list registered webhooks (viewer+, Req 9.1)
// ---------------------------------------------------------------------------
webhookRouter.get(
  '/',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    const configs = await WebhookConfig.find({ orgId: req.params.orgId, isActive: true })
      .select('-secret') // never expose the signing secret
      .sort({ createdAt: -1 })
      .lean();
    res.json(configs);
  }
);

// ---------------------------------------------------------------------------
// POST /orgs/:orgId/webhooks — register a webhook URL (admin+, Req 9.1)
// ---------------------------------------------------------------------------
webhookRouter.post(
  '/',
  authenticate,
  requireRole('admin'),
  async (req: Request, res: Response): Promise<void> => {
    const { url } = req.body as { url?: string };
    if (!url || typeof url !== 'string' || !url.trim()) {
      res.status(422).json({ error: 'url is required' });
      return;
    }

    const ipAddress = (req.headers['x-forwarded-for'] as string) ?? req.socket.remoteAddress ?? '0.0.0.0';

    try {
      const config = await register(req.params.orgId, url.trim(), req.user!.sub, ipAddress);
      // Return config without the secret — secret is for signing only
      res.status(201).json({
        _id:       config._id,
        orgId:     config.orgId,
        url:       config.url,
        isActive:  config.isActive,
        createdAt: config.createdAt,
      });
    } catch (err) {
      if (err instanceof WebhookError) {
        res.status(err.statusCode).json({ error: err.message });
        return;
      }
      throw err;
    }
  }
);

// ---------------------------------------------------------------------------
// DELETE /orgs/:orgId/webhooks/:webhookId — deactivate a webhook (admin+, Req 9.1)
// ---------------------------------------------------------------------------
webhookRouter.delete(
  '/:webhookId',
  authenticate,
  requireRole('admin'),
  async (req: Request, res: Response): Promise<void> => {
    const config = await WebhookConfig.findOne({
      _id:   req.params.webhookId,
      orgId: req.params.orgId,
    });

    if (!config) {
      res.status(404).json({ error: 'Webhook not found' });
      return;
    }

    config.isActive = false;
    await config.save();

    const ipAddress = (req.headers['x-forwarded-for'] as string) ?? req.socket.remoteAddress ?? '0.0.0.0';

    await writeAuditLog({
      actorUserId:        new Types.ObjectId(req.user!.sub),
      orgId:              new Types.ObjectId(req.params.orgId),
      action:             'webhook.deleted',
      targetResourceType: 'webhook',
      targetResourceId:   req.params.webhookId,
      ipAddress,
      timestamp:          new Date(),
    });

    res.status(204).send();
  }
);

// ---------------------------------------------------------------------------
// GET /orgs/:orgId/webhooks/:webhookId/deliveries — delivery log (viewer+, Req 9.5)
// ---------------------------------------------------------------------------
webhookRouter.get(
  '/:webhookId/deliveries',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    const deliveries = await getDeliveryLog(req.params.orgId, req.params.webhookId);
    res.json(deliveries);
  }
);
