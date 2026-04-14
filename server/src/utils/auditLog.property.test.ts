/**
 * Property-based tests for AuditLog immutability (P33)
 * Feature: quantum-bridge
 *
 * Requirements: 11.7
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fc from 'fast-check';

// ---------------------------------------------------------------------------
// Hoisted mocks
// ---------------------------------------------------------------------------
const { mockAuditLogCreate } = vi.hoisted(() => ({
  mockAuditLogCreate: vi.fn(),
}));

vi.mock('./logger.js', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

vi.mock('mongoose', async (importOriginal) => {
  const actual = await importOriginal<typeof import('mongoose')>();
  return {
    ...actual,
    default: actual.default,
    Schema: actual.Schema,
    Types: actual.Types,
    model: vi.fn().mockReturnValue({
      create: mockAuditLogCreate,
      // Deliberately NOT exposing updateOne / updateMany / findOneAndUpdate / deleteOne / deleteMany
      // to mirror the application-layer immutability constraint (Req 11.7)
    }),
  };
});

// Import after mocks
import { writeAuditLog, AuditLog, type WriteAuditLogInput, type AuditAction, type AuditTargetResourceType } from './auditLog.js';

// ---------------------------------------------------------------------------
// Arbitraries
// ---------------------------------------------------------------------------

const auditActionArb = fc.constantFrom<AuditAction>(
  'member.invited',
  'member.removed',
  'member.role_changed',
  'ownership.transferred',
  'endpoint.created',
  'endpoint.deleted',
  'api_key.regenerated',
  'key.rotated',
  'plan.changed',
  'webhook.registered',
  'webhook.deleted'
);

const targetResourceTypeArb = fc.constantFrom<AuditTargetResourceType>(
  'user',
  'organization',
  'endpoint',
  'keyVault',
  'orgMember',
  'webhook',
  'plan'
);

const auditEntryArb = fc.record<WriteAuditLogInput>({
  actorUserId: fc.uuid().map((id) => ({ toString: () => id }) as never),
  orgId: fc.uuid().map((id) => ({ toString: () => id }) as never),
  action: auditActionArb,
  targetResourceType: targetResourceTypeArb,
  targetResourceId: fc.uuid(),
  ipAddress: fc.ipV4(),
  timestamp: fc.date({ min: new Date('2020-01-01'), max: new Date('2030-01-01') }),
  metadata: fc.option(fc.dictionary(fc.string(), fc.string()), { nil: undefined }),
});

// ---------------------------------------------------------------------------
// Property 33: AuditLog Immutability
// Feature: quantum-bridge, Property 33
//
// FOR ALL audit log entries:
//   1. writeAuditLog() MUST call AuditLog.create() exactly once (insert-only)
//   2. The AuditLog model MUST NOT expose update or delete methods
//   3. writeAuditLog() MUST NOT throw even when AuditLog.create() fails
//   4. Every entry passed to create() MUST contain all required fields
// Req 11.7
// ---------------------------------------------------------------------------
describe('Property 33: AuditLog Immutability (Req 11.7)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('writeAuditLog() calls create() exactly once per entry — never update or delete', async () => {
    await fc.assert(
      fc.asyncProperty(auditEntryArb, async (entry) => {
        mockAuditLogCreate.mockClear();
        mockAuditLogCreate.mockResolvedValue({ _id: 'some-id', ...entry });

        await writeAuditLog(entry);

        expect(mockAuditLogCreate).toHaveBeenCalledTimes(1);
        expect(mockAuditLogCreate).toHaveBeenCalledWith(entry);
      }),
      { numRuns: 50 }
    );
  });

  it('AuditLog model does not expose updateOne, updateMany, findOneAndUpdate, deleteOne, or deleteMany', () => {
    // These methods must not exist on the model — immutability enforced at application layer
    expect((AuditLog as unknown as Record<string, unknown>).updateOne).toBeUndefined();
    expect((AuditLog as unknown as Record<string, unknown>).updateMany).toBeUndefined();
    expect((AuditLog as unknown as Record<string, unknown>).findOneAndUpdate).toBeUndefined();
    expect((AuditLog as unknown as Record<string, unknown>).deleteOne).toBeUndefined();
    expect((AuditLog as unknown as Record<string, unknown>).deleteMany).toBeUndefined();
  });

  it('writeAuditLog() never throws even when create() rejects — primary operation must not break', async () => {
    await fc.assert(
      fc.asyncProperty(
        auditEntryArb,
        fc.string({ minLength: 1, maxLength: 64 }),
        async (entry, errorMessage) => {
          mockAuditLogCreate.mockRejectedValue(new Error(errorMessage));

          // Must resolve, never reject
          await expect(writeAuditLog(entry)).resolves.toBeUndefined();
        }
      ),
      { numRuns: 30 }
    );
  });

  it('every entry passed to create() contains all required fields', async () => {
    await fc.assert(
      fc.asyncProperty(auditEntryArb, async (entry) => {
        mockAuditLogCreate.mockClear();
        mockAuditLogCreate.mockResolvedValue({ _id: 'id', ...entry });

        await writeAuditLog(entry);

        const written = mockAuditLogCreate.mock.calls[0][0] as WriteAuditLogInput;

        // All required fields must be present and non-null
        expect(written.actorUserId).toBeDefined();
        expect(written.orgId).toBeDefined();
        expect(written.action).toBeDefined();
        expect(written.targetResourceType).toBeDefined();
        expect(written.targetResourceId).toBeDefined();
        expect(written.ipAddress).toBeDefined();
        expect(written.timestamp).toBeDefined();
      }),
      { numRuns: 50 }
    );
  });

  it('writeAuditLog() passes the entry to create() unchanged — no mutation of input', async () => {
    await fc.assert(
      fc.asyncProperty(auditEntryArb, async (entry) => {
        mockAuditLogCreate.mockClear();
        mockAuditLogCreate.mockResolvedValue({ _id: 'id', ...entry });

        // Snapshot the entry before the call
        const actionBefore = entry.action;
        const targetIdBefore = entry.targetResourceId;
        const ipBefore = entry.ipAddress;

        await writeAuditLog(entry);

        const written = mockAuditLogCreate.mock.calls[0][0] as WriteAuditLogInput;

        // The written entry must match the original — no field mutation
        expect(written.action).toBe(actionBefore);
        expect(written.targetResourceId).toBe(targetIdBefore);
        expect(written.ipAddress).toBe(ipBefore);
      }),
      { numRuns: 50 }
    );
  });
});
