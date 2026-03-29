import { Request, Response, NextFunction } from 'express';
import mongoose, { Schema, model, models } from 'mongoose';

type OrgRole = 'owner' | 'admin' | 'viewer';

// Minimal OrgMember model — used only for role lookup here.
// The full model will be defined in the organization module (task 2.1).
interface IOrgMemberLean {
  orgId: mongoose.Types.ObjectId;
  userId: mongoose.Types.ObjectId;
  role: OrgRole;
  status: 'active' | 'pending';
}

const orgMemberSchema = new Schema<IOrgMemberLean>({
  orgId: { type: Schema.Types.ObjectId, required: true },
  userId: { type: Schema.Types.ObjectId, required: true },
  role: { type: String, enum: ['owner', 'admin', 'viewer'], required: true },
  status: { type: String, enum: ['active', 'pending'], required: true },
});

// Reuse existing model if already registered (avoids OverwriteModelError in tests)
const OrgMember =
  (models['OrgMember'] as mongoose.Model<IOrgMemberLean>) ||
  model<IOrgMemberLean>('OrgMember', orgMemberSchema);

// Role hierarchy: owner > admin > viewer
const ROLE_RANK: Record<OrgRole, number> = { owner: 3, admin: 2, viewer: 1 };

/**
 * Returns middleware that enforces a minimum role for the requesting user
 * within the organization identified by req.params.orgId.
 *
 * Requires authenticate() to run first (req.user must be set).
 * Returns 403 if the user's role is below the required minimum.
 */
export function requireRole(minimumRole: OrgRole) {
  return async (req: Request, res: Response, next: NextFunction): Promise<void> => {
    const user = req.user;
    if (!user) {
      res.status(401).json({ error: 'Unauthorized' });
      return;
    }

    const { orgId } = req.params;
    if (!orgId) {
      res.status(400).json({ error: 'Missing orgId' });
      return;
    }

    const member = await OrgMember.findOne({
      orgId: new mongoose.Types.ObjectId(orgId),
      userId: new mongoose.Types.ObjectId(user.sub),
      status: 'active',
    }).lean();

    if (!member) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    if (ROLE_RANK[member.role] < ROLE_RANK[minimumRole]) {
      res.status(403).json({ error: 'Forbidden' });
      return;
    }

    next();
  };
}
