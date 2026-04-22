import { Router, Request, Response } from 'express';
import { authenticate } from '../../middleware/authenticate.js';
import { requireRole } from '../../middleware/requireRole.js';
import * as OrgService from './orgService.js';
import { keyVaultService } from '../keyVault/keyVaultService.js';

export const orgRouter = Router();

// ---------------------------------------------------------------------------
// Organization CRUD
// ---------------------------------------------------------------------------

// POST /orgs — create a new organization (Req 3.1)
orgRouter.post('/', authenticate, async (req: Request, res: Response): Promise<void> => {
  try {
    const { name } = req.body as { name?: string };
    if (!name || typeof name !== 'string' || !name.trim()) {
      res.status(422).json({ error: 'name is required' });
      return;
    }
    const org = await OrgService.create(req.user!.sub, name.trim());
    res.status(201).json(org);
  } catch (err: unknown) {
    if (err instanceof OrgService.ConflictError) {
      res.status(409).json({ error: err.message });
      return;
    }
    throw err;
  }
});

// GET /orgs/:orgId — get org details (viewer+)
orgRouter.get(
  '/:orgId',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { Organization } = await import('./Organization.js');
      const org = await Organization.findById(req.params.orgId).lean();
      if (!org) {
        res.status(404).json({ error: 'Organization not found' });
        return;
      }
      res.json(org);
    } catch {
      throw new Error('Failed to fetch organization');
    }
  }
);

// DELETE /orgs/:orgId — cascade delete org and all associated data (owner only, Req 16.6)
orgRouter.delete(
  '/:orgId',
  authenticate,
  requireRole('owner'),
  async (req: Request, res: Response): Promise<void> => {
    const { orgId } = req.params;
    try {
      const [
        { Organization }  ,
        { OrgMember }     ,
        { Endpoint }      ,
        { KeyVault }      ,
        { ProxyLog }      ,
        { AuditLog }      ,
        { WebhookConfig } ,
      ] = await Promise.all([
        import('./Organization.js'),
        import('./OrgMember.js'),
        import('../endpoint/Endpoint.js'),
        import('../keyVault/KeyVault.js'),
        import('../proxy/ProxyLog.js'),
        import('../../utils/auditLog.js'),
        import('../webhook/WebhookConfig.js'),
      ]);

      await Promise.all([
        Endpoint.deleteMany({ orgId }),
        KeyVault.deleteMany({ orgId }),
        OrgMember.deleteMany({ orgId }),
        ProxyLog.deleteMany({ orgId }),
        AuditLog.deleteMany({ orgId }),
        WebhookConfig.deleteMany({ orgId }),
      ]);

      await Organization.findByIdAndDelete(orgId);

      res.status(204).send();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      res.status(500).json({ error: msg });
    }
  }
);

// ---------------------------------------------------------------------------
// Member management
// ---------------------------------------------------------------------------

// GET /orgs/:orgId/members — list members (viewer+)
orgRouter.get(
  '/:orgId/members',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    const members = await OrgService.getMembers(req.params.orgId);
    res.json(members);
  }
);

// POST /orgs/:orgId/members/invite — invite a member (admin+, Req 3.4)
orgRouter.post(
  '/:orgId/members/invite',
  authenticate,
  requireRole('admin'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { email, role } = req.body as { email?: string; role?: string };
      if (!email || (role !== 'admin' && role !== 'viewer')) {
        res.status(422).json({ error: 'email and role (admin|viewer) are required' });
        return;
      }
      await OrgService.invite(req.params.orgId, req.user!.sub, email, role);
      res.status(204).send();
    } catch (err: unknown) {
      if (err instanceof OrgService.ForbiddenError) {
        res.status(403).json({ error: err.message });
        return;
      }
      if (err instanceof OrgService.NotFoundError) {
        res.status(404).json({ error: err.message });
        return;
      }
      throw err;
    }
  }
);

// POST /orgs/:orgId/members/accept-invite — accept an invitation (Req 3.5)
orgRouter.post(
  '/:orgId/members/accept-invite',
  authenticate,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { token } = req.body as { token?: string };
      if (!token) {
        res.status(422).json({ error: 'token is required' });
        return;
      }
      await OrgService.acceptInvite(token, req.user!.sub);
      res.status(204).send();
    } catch (err: unknown) {
      if (err instanceof OrgService.NotFoundError) {
        res.status(404).json({ error: err.message });
        return;
      }
      throw err;
    }
  }
);

// DELETE /orgs/:orgId/members/:userId — remove a member (admin+, Req 3.6)
orgRouter.delete(
  '/:orgId/members/:userId',
  authenticate,
  requireRole('admin'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      await OrgService.removeMember(req.params.orgId, req.user!.sub, req.params.userId);
      res.status(204).send();
    } catch (err: unknown) {
      if (err instanceof OrgService.ForbiddenError) {
        res.status(403).json({ error: err.message });
        return;
      }
      if (err instanceof OrgService.NotFoundError) {
        res.status(404).json({ error: err.message });
        return;
      }
      throw err;
    }
  }
);

// POST /orgs/:orgId/members/transfer-ownership — transfer ownership (owner only, Req 3.8)
orgRouter.post(
  '/:orgId/members/transfer-ownership',
  authenticate,
  requireRole('owner'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { newOwnerId } = req.body as { newOwnerId?: string };
      if (!newOwnerId) {
        res.status(422).json({ error: 'newOwnerId is required' });
        return;
      }
      await OrgService.transferOwnership(req.params.orgId, req.user!.sub, newOwnerId);
      res.status(204).send();
    } catch (err: unknown) {
      if (err instanceof OrgService.ForbiddenError) {
        res.status(403).json({ error: err.message });
        return;
      }
      if (err instanceof OrgService.NotFoundError) {
        res.status(404).json({ error: err.message });
        return;
      }
      if (err instanceof OrgService.ConflictError) {
        res.status(409).json({ error: err.message });
        return;
      }
      throw err;
    }
  }
);

// ---------------------------------------------------------------------------
// Key management (Req 4.6, 4.8)
// ---------------------------------------------------------------------------

// GET /orgs/:orgId/keys — get current public keys (viewer+)
orgRouter.get(
  '/:orgId/keys',
  authenticate,
  requireRole('viewer'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const keys = await keyVaultService.getPublicKeys(req.params.orgId);
      res.json(keys);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      res.status(404).json({ error: msg });
    }
  }
);

// POST /orgs/:orgId/keys/rotate — trigger manual key rotation (admin+, Req 4.8)
orgRouter.post(
  '/:orgId/keys/rotate',
  authenticate,
  requireRole('admin'),
  async (req: Request, res: Response): Promise<void> => {
    try {
      const ipAddress = (req.headers['x-forwarded-for'] as string) ?? req.socket.remoteAddress ?? '0.0.0.0';
      await keyVaultService.rotate(req.params.orgId, req.user!.sub, ipAddress);
      res.status(204).send();
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Unknown error';
      res.status(400).json({ error: msg });
    }
  }
);
