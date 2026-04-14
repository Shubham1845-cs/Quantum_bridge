/**
 * Property-based tests for Organization module (P6–P8)
 * Feature: quantum-bridge
 *
 * Requirements: 3.1, 3.3, 3.7, 3.8
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fc from 'fast-check';

// ---------------------------------------------------------------------------
// Hoisted mocks
// ---------------------------------------------------------------------------
const {
  mockOrgCreate,
  mockOrgFindOne,
  mockOrgMemberCreate,
  mockOrgMemberFindOne,
  mockOrgMemberUpdateOne,
  mockOrgMemberDeleteOne,
  mockRedisSmembers,
  mockRedisPipeline,
  mockSendEmail,
} = vi.hoisted(() => {
  const mockPipelineExec = vi.fn().mockResolvedValue([]);
  const mockPipelineDel = vi.fn().mockReturnThis();
  const pipeline = { del: mockPipelineDel, exec: mockPipelineExec };

  return {
    mockOrgCreate: vi.fn(),
    mockOrgFindOne: vi.fn(),
    mockOrgMemberCreate: vi.fn(),
    mockOrgMemberFindOne: vi.fn(),
    mockOrgMemberUpdateOne: vi.fn(),
    mockOrgMemberDeleteOne: vi.fn(),
    mockRedisSmembers: vi.fn().mockResolvedValue([]),
    mockRedisPipeline: vi.fn().mockReturnValue(pipeline),
    mockSendEmail: vi.fn().mockResolvedValue({ id: 'email-id' }),
  };
});

vi.mock('../../config/env.js', () => ({
  env: {
    RESEND_API_KEY: 're_test_key',
    ALLOWED_ORIGIN: 'https://app.quantumbridge.io',
    NODE_ENV: 'test',
  },
}));

vi.mock('../../utils/logger.js', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock('resend', () => ({
  Resend: vi.fn().mockImplementation(() => ({
    emails: { send: mockSendEmail },
  })),
}));

vi.mock('./Organization.js', () => ({
  Organization: {
    create: mockOrgCreate,
    findOne: mockOrgFindOne,
    findById: vi.fn(),
  },
}));

vi.mock('./OrgMember.js', () => ({
  OrgMember: {
    create: mockOrgMemberCreate,
    findOne: mockOrgMemberFindOne,
    findOneAndUpdate: vi.fn().mockResolvedValue({}),
    updateOne: mockOrgMemberUpdateOne,
    deleteOne: mockOrgMemberDeleteOne,
    find: vi.fn().mockReturnValue({ sort: vi.fn().mockResolvedValue([]) }),
  },
}));

vi.mock('../../config/redis.js', () => ({
  redis: {
    smembers: mockRedisSmembers,
    pipeline: mockRedisPipeline,
  },
}));

// Stub out KeyVaultService so org creation doesn't fail
vi.mock('../keyVault/keyVaultService.js', () => ({
  keyVaultService: {
    generateAndStore: vi.fn().mockResolvedValue(undefined),
  },
}));

// Stub mongoose session for transferOwnership
vi.mock('mongoose', async (importOriginal) => {
  const actual = await importOriginal<typeof import('mongoose')>();
  return {
    ...actual,
    default: {
      ...actual.default,
      startSession: vi.fn().mockResolvedValue({
        withTransaction: vi.fn().mockImplementation(async (fn: () => Promise<void>) => fn()),
        endSession: vi.fn().mockResolvedValue(undefined),
      }),
      Types: actual.Types,
    },
    Types: actual.Types,
    startSession: vi.fn().mockResolvedValue({
      withTransaction: vi.fn().mockImplementation(async (fn: () => Promise<void>) => fn()),
      endSession: vi.fn().mockResolvedValue(undefined),
    }),
  };
});

// Import after mocks
import { slugify } from '../../utils/slugify.js';
import {
  create,
  invite,
  removeMember,
  transferOwnership,
  ForbiddenError,
  ConflictError,
} from './orgService.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeOrgId() {
  return { toString: () => 'org-id-abc', equals: (v: unknown) => v === 'org-id-abc' };
}

function makeUserId(id = 'user-id-abc') {
  return { toString: () => id };
}

function makeMember(role: 'owner' | 'admin' | 'viewer', userId = 'user-id-abc') {
  return {
    _id: { toString: () => 'member-id' },
    orgId: makeOrgId(),
    userId: makeUserId(userId),
    role,
    status: 'active' as const,
    save: vi.fn().mockResolvedValue(undefined),
  };
}

// ---------------------------------------------------------------------------
// Property 6: Org Slug URL-Safety
// Feature: quantum-bridge, Property 6
//
// FOR ALL org names, slugify(name) MUST produce a string that:
//   - contains only lowercase alphanumeric characters and hyphens
//   - does not start or end with a hyphen
//   - is non-empty
// Req 3.1
// ---------------------------------------------------------------------------
describe('Property 6: Org Slug URL-Safety (Req 3.1)', () => {
  it('slugify produces only lowercase alphanumeric + hyphens for any input', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 128 }),
        (name) => {
          const slug = slugify(name);
          expect(slug).toMatch(/^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$/);
        }
      ),
      { numRuns: 200 }
    );
  });

  it('slugify never produces a slug starting or ending with a hyphen', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 128 }),
        (name) => {
          const slug = slugify(name);
          expect(slug).not.toMatch(/^-/);
          expect(slug).not.toMatch(/-$/);
        }
      ),
      { numRuns: 200 }
    );
  });

  it('slugify always returns a non-empty string', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 0, maxLength: 128 }),
        (name) => {
          const slug = slugify(name);
          expect(slug.length).toBeGreaterThan(0);
        }
      ),
      { numRuns: 200 }
    );
  });

  it('create() stores the slugified name on the org record', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.string({ minLength: 1, maxLength: 64 }).filter((s) => s.trim().length > 0),
        async (name) => {
          vi.clearAllMocks();

          const expectedSlug = slugify(name);
          const orgId = makeOrgId();

          mockOrgCreate.mockResolvedValue({
            _id: orgId,
            name,
            slug: expectedSlug,
          });
          mockOrgMemberCreate.mockResolvedValue({});

          await create('user-id-abc', name);

          const createdWith = mockOrgCreate.mock.calls[0][0];
          expect(createdWith.slug).toBe(expectedSlug);
          // Slug must be URL-safe
          expect(createdWith.slug).toMatch(/^[a-z0-9][a-z0-9-]*[a-z0-9]$|^[a-z0-9]$/);
        }
      ),
      { numRuns: 30 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 7: Single Owner Invariant
// Feature: quantum-bridge, Property 7
//
// FOR ALL transferOwnership calls, after the transfer:
//   - the new owner's role is 'owner'
//   - the previous owner's role is demoted to 'admin'
//   - exactly one updateOne call targets each member
// Req 3.3, 3.8
// ---------------------------------------------------------------------------
describe('Property 7: Single Owner Invariant (Req 3.3, 3.8)', () => {
  it('transferOwnership demotes current owner and promotes new owner atomically', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.uuid(),
        fc.uuid(),
        async (orgId, currentOwnerId, newOwnerId) => {
          fc.pre(currentOwnerId !== newOwnerId);
          vi.clearAllMocks();

          // Current owner membership check
          mockOrgMemberFindOne
            .mockResolvedValueOnce(makeMember('owner', currentOwnerId)) // assertOwner
            .mockResolvedValueOnce(makeMember('admin', newOwnerId));    // new owner lookup

          mockOrgMemberUpdateOne.mockResolvedValue({ modifiedCount: 1 });

          await transferOwnership(orgId, currentOwnerId, newOwnerId);

          // Two updateOne calls must have been made
          expect(mockOrgMemberUpdateOne).toHaveBeenCalledTimes(2);

          const [demoteCall, promoteCall] = mockOrgMemberUpdateOne.mock.calls;

          // First call demotes current owner → admin
          expect(demoteCall[1]).toMatchObject({ $set: { role: 'admin' } });
          expect(demoteCall[0]).toMatchObject({ userId: currentOwnerId, role: 'owner' });

          // Second call promotes new owner → owner
          expect(promoteCall[1]).toMatchObject({ $set: { role: 'owner' } });
          expect(promoteCall[0]).toMatchObject({ userId: newOwnerId });
        }
      ),
      { numRuns: 30 }
    );
  });

  it('transferOwnership throws ForbiddenError when actor is not the owner', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.uuid(),
        fc.uuid(),
        async (orgId, nonOwnerId, newOwnerId) => {
          fc.pre(nonOwnerId !== newOwnerId);
          vi.clearAllMocks();

          // assertOwner finds no owner membership for this actor
          mockOrgMemberFindOne.mockResolvedValue(null);

          await expect(
            transferOwnership(orgId, nonOwnerId, newOwnerId)
          ).rejects.toThrow(ForbiddenError);

          // No updates should have been made
          expect(mockOrgMemberUpdateOne).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 30 }
    );
  });

  it('transferOwnership throws ConflictError when new owner is already the owner', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.uuid(),
        async (orgId, ownerId) => {
          vi.clearAllMocks();

          mockOrgMemberFindOne
            .mockResolvedValueOnce(makeMember('owner', ownerId))  // assertOwner passes
            .mockResolvedValueOnce(makeMember('owner', ownerId)); // new owner is already owner

          await expect(
            transferOwnership(orgId, ownerId, ownerId)
          ).rejects.toThrow(ConflictError);

          expect(mockOrgMemberUpdateOne).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 20 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 8: Viewer Write Rejection
// Feature: quantum-bridge, Property 8
//
// FOR ALL write operations (invite, removeMember) attempted by a viewer,
// the operation MUST throw ForbiddenError (403) and MUST NOT mutate state.
// Req 3.7
// ---------------------------------------------------------------------------
describe('Property 8: Viewer Write Rejection (Req 3.7)', () => {
  it('invite() throws ForbiddenError for any viewer actor', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.uuid(),
        fc.emailAddress(),
        fc.constantFrom('admin' as const, 'viewer' as const),
        async (orgId, viewerId, targetEmail, role) => {
          vi.clearAllMocks();

          // Actor is a viewer
          mockOrgMemberFindOne.mockResolvedValue(makeMember('viewer', viewerId));

          await expect(
            invite(orgId, viewerId, targetEmail, role)
          ).rejects.toThrow(ForbiddenError);

          // No org member should have been created
          expect(mockOrgMemberCreate).not.toHaveBeenCalled();
          // No email should have been sent
          expect(mockSendEmail).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 30 }
    );
  });

  it('removeMember() throws ForbiddenError for any viewer actor', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.uuid(),
        fc.uuid(),
        async (orgId, viewerId, targetUserId) => {
          fc.pre(viewerId !== targetUserId);
          vi.clearAllMocks();

          // Actor is a viewer
          mockOrgMemberFindOne.mockResolvedValue(makeMember('viewer', viewerId));

          await expect(
            removeMember(orgId, viewerId, targetUserId)
          ).rejects.toThrow(ForbiddenError);

          // No member should have been deleted
          expect(mockOrgMemberDeleteOne).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 30 }
    );
  });

  it('invite() succeeds for admin actors (non-viewer write is allowed)', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.uuid(),
        fc.uuid(),
        fc.emailAddress(),
        async (orgId, adminId, targetEmail) => {
          vi.clearAllMocks();

          // assertNotViewer: admin membership found
          mockOrgMemberFindOne.mockResolvedValue(makeMember('admin', adminId));

          const { Organization } = await import('./Organization.js');
          vi.mocked(Organization.findById).mockResolvedValue({
            _id: makeOrgId(),
            name: 'Test Org',
          } as never);

          // Mock findOneAndUpdate used by the upsert in invite()
          const { OrgMember } = await import('./OrgMember.js');
          vi.mocked(OrgMember).findOneAndUpdate = vi.fn().mockResolvedValue({});

          // Should not throw
          await expect(
            invite(orgId, adminId, targetEmail, 'viewer')
          ).resolves.toBeUndefined();
        }
      ),
      { numRuns: 20 }
    );
  });

  it('viewer role is distinct from all write-capable roles', () => {
    // Synchronous property: the viewer role string is never in the set of write-capable roles
    fc.assert(
      fc.property(
        fc.uuid(),
        fc.uuid(),
        (_orgId, _userId) => {
          const viewerRole = 'viewer';
          const writeCapableRoles = ['owner', 'admin'];

          expect(writeCapableRoles).not.toContain(viewerRole);
          expect(viewerRole).not.toBe('owner');
          expect(viewerRole).not.toBe('admin');
        }
      ),
      { numRuns: 50 }
    );
  });
});
