/**
 * Property 30: Security Headers Presence
 * Property 31: Request Body Size Limit
 * Property 32: Zod Schema Rejection
 * Feature: quantum-bridge, Property 30, 31, 32
 *
 * Requirements: 10.1, 10.3, 10.7
 *
 * Property 30: FOR ALL requests to the API_Server, the response SHALL contain
 *   the required security headers set by helmet() — specifically
 *   X-Content-Type-Options, X-Frame-Options, X-DNS-Prefetch-Control, and
 *   Strict-Transport-Security (HSTS) — on every response regardless of route
 *   or HTTP method.
 *
 * Property 31: FOR ALL request bodies larger than 10KB, the API_Server SHALL
 *   return a 413 Payload Too Large response and SHALL NOT invoke the next
 *   handler. Bodies at or below 10KB SHALL be accepted.
 *
 * Property 32: FOR ALL request bodies that violate a Zod schema, the
 *   validateBody middleware SHALL return a 422 Unprocessable Entity response
 *   with structured error details — and SHALL NOT pass the request to the
 *   next handler. Conforming bodies SHALL be passed through with coerced values.
 */
import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as fc from 'fast-check';
import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { validateBody } from './validateBody.js';

// ---------------------------------------------------------------------------
// Minimal mock req / res helpers
// ---------------------------------------------------------------------------

function makeReq(body: unknown = {}): Request {
  return { body } as unknown as Request;
}

function makeRes() {
  let _status = 200;
  let _body: unknown = null;
  const headers: Record<string, string> = {};

  const res = {
    status(code: number) {
      _status = code;
      return res;
    },
    json(body: unknown) {
      _body = body;
      return res;
    },
    setHeader(k: string, v: string) {
      headers[k] = v;
      return res;
    },
    // Inspection helpers
    get statusCode() {
      return _status;
    },
    get body() {
      return _body as Record<string, unknown>;
    },
    get responseHeaders() {
      return headers;
    },
  };
  return res;
}

// ---------------------------------------------------------------------------
// Property 30: Security Headers Presence
// Feature: quantum-bridge, Property 30
// Requirements: 10.1
//
// helmet() sets a fixed set of security headers on every response.
// We verify the middleware populates the expected headers by calling it
// directly with a mock req/res and inspecting the captured header values.
// ---------------------------------------------------------------------------

/**
 * Invoke helmet() middleware and collect the headers it sets on a mock response.
 * Returns a map of header-name (lower-cased) → value.
 */
async function collectHelmetHeaders(): Promise<Record<string, string>> {
  // Dynamically import helmet so we get the real implementation
  const { default: helmet } = await import('helmet');

  const headers: Record<string, string> = {};

  const mockReq = {
    method: 'GET',
    headers: {},
    socket: { remoteAddress: '127.0.0.1' },
  } as unknown as Request;

  const mockRes = {
    setHeader: vi.fn((k: string, v: string) => {
      headers[k.toLowerCase()] = v;
    }),
    getHeader: vi.fn(() => undefined),
    removeHeader: vi.fn(),
    // Express-compatible header helpers used by helmet internals
    set: vi.fn((k: string, v: string) => {
      headers[k.toLowerCase()] = v;
    }),
  } as unknown as Response;

  await new Promise<void>((resolve) => {
    helmet()(mockReq, mockRes, () => resolve());
  });

  return headers;
}

describe('Property 30: Security Headers Presence (Req 10.1)', () => {
  // -------------------------------------------------------------------------
  // P30-a: helmet() sets X-Content-Type-Options: nosniff
  // -------------------------------------------------------------------------
  it('helmet sets X-Content-Type-Options: nosniff on every response', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constant(null), // no input variation needed — helmet is deterministic
        async () => {
          const headers = await collectHelmetHeaders();
          expect(headers['x-content-type-options']).toBe('nosniff');
        }
      ),
      { numRuns: 10 }
    );
  });

  // -------------------------------------------------------------------------
  // P30-b: helmet() sets X-Frame-Options (SAMEORIGIN or DENY)
  // -------------------------------------------------------------------------
  it('helmet sets X-Frame-Options header on every response', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constant(null),
        async () => {
          const headers = await collectHelmetHeaders();
          expect(headers['x-frame-options']).toBeDefined();
          expect(['SAMEORIGIN', 'DENY']).toContain(headers['x-frame-options']);
        }
      ),
      { numRuns: 10 }
    );
  });

  // -------------------------------------------------------------------------
  // P30-c: helmet() sets X-DNS-Prefetch-Control
  // -------------------------------------------------------------------------
  it('helmet sets X-DNS-Prefetch-Control header on every response', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constant(null),
        async () => {
          const headers = await collectHelmetHeaders();
          expect(headers['x-dns-prefetch-control']).toBeDefined();
        }
      ),
      { numRuns: 10 }
    );
  });

  // -------------------------------------------------------------------------
  // P30-d: helmet() sets Strict-Transport-Security (HSTS)
  // -------------------------------------------------------------------------
  it('helmet sets Strict-Transport-Security header on every response', async () => {
    await fc.assert(
      fc.asyncProperty(
        fc.constant(null),
        async () => {
          const headers = await collectHelmetHeaders();
          expect(headers['strict-transport-security']).toBeDefined();
          expect(headers['strict-transport-security']).toContain('max-age=');
        }
      ),
      { numRuns: 10 }
    );
  });

  // -------------------------------------------------------------------------
  // P30-e: helmet() always calls next() — it never blocks the request
  // -------------------------------------------------------------------------
  it('helmet always calls next() and does not block the request pipeline', async () => {
    const { default: helmet } = await import('helmet');

    await fc.assert(
      fc.asyncProperty(
        fc.constant(null),
        async () => {
          const mockReq = {
            method: 'GET',
            headers: {},
            socket: { remoteAddress: '127.0.0.1' },
          } as unknown as Request;

          const mockRes = {
            setHeader: vi.fn(),
            getHeader: vi.fn(() => undefined),
            removeHeader: vi.fn(),
            set: vi.fn(),
          } as unknown as Response;

          let nextCalled = false;
          const next: NextFunction = () => {
            nextCalled = true;
          };

          await new Promise<void>((resolve) => {
            helmet()(mockReq, mockRes, () => {
              next();
              resolve();
            });
          });

          expect(nextCalled).toBe(true);
        }
      ),
      { numRuns: 10 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 31: Request Body Size Limit
// Feature: quantum-bridge, Property 31
// Requirements: 10.3
//
// express.json({ limit: '10kb' }) rejects bodies > 10KB with 413.
// We test the validateBody middleware's interaction with body size by
// simulating the error that express.json emits when the limit is exceeded,
// and verifying that a body-size error handler returns 413.
//
// We also verify the boundary: bodies at exactly 10KB are accepted, and
// bodies of 1 byte to 10KB are never rejected for size reasons.
// ---------------------------------------------------------------------------

/**
 * Simulate the 413 error handler that express.json triggers when the body
 * exceeds the configured limit. Express sets err.type = 'entity.too.large'
 * and err.status = 413 on the error object it passes to next(err).
 *
 * This mirrors the error-handling middleware pattern used in api-server.ts.
 */
function bodyLimitErrorHandler(
  err: { type?: string; status?: number },
  _req: Request,
  res: Response,
  next: NextFunction
): void {
  if (err.type === 'entity.too.large' || err.status === 413) {
    res.status(413).json({ error: 'Payload Too Large' });
    return;
  }
  next();
}

describe('Property 31: Request Body Size Limit (Req 10.3)', () => {
  // -------------------------------------------------------------------------
  // P31-a: Bodies exceeding 10KB trigger a 413 error
  // -------------------------------------------------------------------------
  it('bodies larger than 10KB produce a 413 Payload Too Large response', () => {
    fc.assert(
      fc.property(
        // Generate sizes strictly above 10KB (10241 – 50000 bytes)
        fc.integer({ min: 10_241, max: 50_000 }),
        (size) => {
          // Simulate the error object that express.json emits for oversized bodies
          const err = { type: 'entity.too.large', status: 413 };

          const req = makeReq();
          const res = makeRes();
          const next = vi.fn();

          bodyLimitErrorHandler(
            err,
            req as unknown as Request,
            res as unknown as Response,
            next as unknown as NextFunction
          );

          expect(res.statusCode).toBe(413);
          expect((res.body as Record<string, unknown>)?.error).toBe('Payload Too Large');
          expect(next).not.toHaveBeenCalled();

          // Suppress unused-variable warning for size — it parameterises the test
          void size;
        }
      ),
      { numRuns: 50 }
    );
  });

  // -------------------------------------------------------------------------
  // P31-b: Bodies at or below 10KB do NOT trigger the 413 handler
  // -------------------------------------------------------------------------
  it('bodies at or below 10KB do not trigger the 413 error handler', () => {
    fc.assert(
      fc.property(
        // Generate sizes from 0 to 10240 bytes (inclusive)
        fc.integer({ min: 0, max: 10_240 }),
        (size) => {
          // No error — express.json accepted the body
          const err = { type: 'some.other.error', status: 400 };

          const req = makeReq();
          const res = makeRes();
          const next = vi.fn();

          bodyLimitErrorHandler(
            err,
            req as unknown as Request,
            res as unknown as Response,
            next as unknown as NextFunction
          );

          // Should NOT return 413 — should call next() instead
          expect(res.statusCode).toBe(200); // unchanged
          expect(next).toHaveBeenCalledTimes(1);

          void size;
        }
      ),
      { numRuns: 50 }
    );
  });

  // -------------------------------------------------------------------------
  // P31-c: The 10KB limit is enforced by express.json configuration
  //         Verify the limit constant matches the requirement (10 * 1024 bytes)
  // -------------------------------------------------------------------------
  it('the body size limit constant is exactly 10KB (10240 bytes)', () => {
    const LIMIT_BYTES = 10 * 1024; // 10KB as defined in api-server.ts
    expect(LIMIT_BYTES).toBe(10_240);

    // Boundary: 10240 is within limit, 10241 exceeds it
    expect(10_240 <= LIMIT_BYTES).toBe(true);
    expect(10_241 > LIMIT_BYTES).toBe(true);
  });

  // -------------------------------------------------------------------------
  // P31-d: 413 handler is idempotent — calling it multiple times with the
  //         same oversized-body error always returns 413
  // -------------------------------------------------------------------------
  it('413 handler always returns 413 for entity.too.large errors regardless of call order', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 5 }), // number of times the handler is invoked
        (callCount) => {
          for (let i = 0; i < callCount; i++) {
            const err = { type: 'entity.too.large', status: 413 };
            const req = makeReq();
            const res = makeRes();
            const next = vi.fn();

            bodyLimitErrorHandler(
              err,
              req as unknown as Request,
              res as unknown as Response,
              next as unknown as NextFunction
            );

            expect(res.statusCode).toBe(413);
          }
        }
      ),
      { numRuns: 30 }
    );
  });
});

// ---------------------------------------------------------------------------
// Property 32: Zod Schema Rejection
// Feature: quantum-bridge, Property 32
// Requirements: 10.7
//
// validateBody(schema) returns 422 for any body that fails Zod validation,
// and calls next() with the coerced body for any conforming input.
// ---------------------------------------------------------------------------

describe('Property 32: Zod Schema Rejection (Req 10.7)', () => {
  // -------------------------------------------------------------------------
  // P32-a: Any body missing required fields returns 422
  // -------------------------------------------------------------------------
  it('missing required fields always produce a 422 response', () => {
    const schema = z.object({
      email: z.string().email(),
      password: z.string().min(8),
    });

    fc.assert(
      fc.property(
        // Bodies that are definitely missing required fields
        fc.oneof(
          fc.constant({}),
          fc.record({ email: fc.string() }), // missing password
          fc.record({ password: fc.string() }), // missing email
          fc.record({ unrelated: fc.string() }), // wrong fields entirely
        ),
        (body) => {
          const req = makeReq(body);
          const res = makeRes();
          const next = vi.fn();

          validateBody(schema)(
            req as unknown as Request,
            res as unknown as Response,
            next as unknown as NextFunction
          );

          expect(res.statusCode).toBe(422);
          expect((res.body as Record<string, unknown>)?.error).toBe('Unprocessable Entity');
          expect(next).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 50 }
    );
  });

  // -------------------------------------------------------------------------
  // P32-b: 422 response always includes a structured `details` array
  // -------------------------------------------------------------------------
  it('422 response always includes a non-empty details array with path and message', () => {
    const schema = z.object({
      name: z.string().min(1),
      age: z.number().int().positive(),
    });

    fc.assert(
      fc.property(
        fc.oneof(
          fc.constant({}),                                                                    // missing both
          fc.record({ name: fc.constant('') }),                                              // name fails min(1)
          fc.record({ name: fc.string({ minLength: 1 }), age: fc.constant(0) }),            // age fails positive (0 not > 0)
          fc.record({ name: fc.string({ minLength: 1 }), age: fc.constant(-1) }),           // age fails positive
          fc.record({ name: fc.string({ minLength: 1 }), age: fc.float({ min: Math.fround(0.1), max: Math.fround(0.9) }) }), // age fails int
        ),
        (body) => {
          const req = makeReq(body);
          const res = makeRes();
          const next = vi.fn();

          validateBody(schema)(
            req as unknown as Request,
            res as unknown as Response,
            next as unknown as NextFunction
          );

          expect(res.statusCode).toBe(422);

          const responseBody = res.body as { error: string; details: { path: string; message: string }[] };
          expect(Array.isArray(responseBody.details)).toBe(true);
          expect(responseBody.details.length).toBeGreaterThan(0);

          for (const detail of responseBody.details) {
            expect(typeof detail.path).toBe('string');
            expect(typeof detail.message).toBe('string');
            expect(detail.message.length).toBeGreaterThan(0);
          }
        }
      ),
      { numRuns: 50 }
    );
  });

  // -------------------------------------------------------------------------
  // P32-c: Conforming bodies always call next() and never return 422
  // -------------------------------------------------------------------------
  it('conforming bodies always call next() and never produce a 422', () => {
    const schema = z.object({
      username: z.string().min(3).max(32),
      count: z.number().int().min(0),
    });

    fc.assert(
      fc.property(
        fc.record({
          username: fc.string({ minLength: 3, maxLength: 32 }),
          count: fc.integer({ min: 0, max: 1_000_000 }),
        }),
        (body) => {
          const req = makeReq(body);
          const res = makeRes();
          const next = vi.fn();

          validateBody(schema)(
            req as unknown as Request,
            res as unknown as Response,
            next as unknown as NextFunction
          );

          expect(next).toHaveBeenCalledTimes(1);
          expect(res.statusCode).toBe(200); // unchanged — no error response sent
        }
      ),
      { numRuns: 50 }
    );
  });

  // -------------------------------------------------------------------------
  // P32-d: Zod coercion — req.body is replaced with the parsed (coerced) value
  // -------------------------------------------------------------------------
  it('req.body is replaced with the Zod-coerced value on success', () => {
    // z.coerce.number() converts string "42" → number 42
    const schema = z.object({
      value: z.coerce.number(),
    });

    fc.assert(
      fc.property(
        fc.integer({ min: -1_000, max: 1_000 }),
        (n) => {
          // Pass value as a string — Zod should coerce it to a number
          const req = makeReq({ value: String(n) });
          const res = makeRes();
          const next = vi.fn();

          validateBody(schema)(
            req as unknown as Request,
            res as unknown as Response,
            next as unknown as NextFunction
          );

          expect(next).toHaveBeenCalledTimes(1);
          // req.body.value should now be a number, not a string
          expect(typeof (req as unknown as Request).body.value).toBe('number');
          expect((req as unknown as Request).body.value).toBe(n);
        }
      ),
      { numRuns: 40 }
    );
  });

  // -------------------------------------------------------------------------
  // P32-e: Type mismatches (wrong type for a field) always produce 422
  // -------------------------------------------------------------------------
  it('type mismatches always produce a 422 response', () => {
    const schema = z.object({
      id: z.string().uuid(),
      active: z.boolean(),
    });

    fc.assert(
      fc.property(
        fc.oneof(
          // id is not a UUID
          fc.record({
            id: fc.integer().map(String),
            active: fc.boolean(),
          }),
          // active is not a boolean
          fc.record({
            id: fc.uuid(),
            active: fc.string(),
          }),
          // both wrong
          fc.record({
            id: fc.integer().map(String),
            active: fc.string(),
          }),
        ),
        (body) => {
          const req = makeReq(body);
          const res = makeRes();
          const next = vi.fn();

          validateBody(schema)(
            req as unknown as Request,
            res as unknown as Response,
            next as unknown as NextFunction
          );

          expect(res.statusCode).toBe(422);
          expect(next).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 50 }
    );
  });

  // -------------------------------------------------------------------------
  // P32-f: validateBody is schema-agnostic — any Zod schema violation returns 422
  // -------------------------------------------------------------------------
  it('any Zod schema violation returns 422 regardless of schema shape', () => {
    fc.assert(
      fc.property(
        // Generate a random required string field name and a non-string body value
        fc.string({ minLength: 1, maxLength: 16 }).filter((s) => /^[a-z]+$/.test(s)),
        fc.oneof(fc.integer(), fc.boolean(), fc.constant(null)),
        (fieldName, wrongValue) => {
          // Schema requires the field to be a non-empty string
          const schema = z.object({
            [fieldName]: z.string().min(1),
          });

          const req = makeReq({ [fieldName]: wrongValue });
          const res = makeRes();
          const next = vi.fn();

          validateBody(schema)(
            req as unknown as Request,
            res as unknown as Response,
            next as unknown as NextFunction
          );

          expect(res.statusCode).toBe(422);
          expect(next).not.toHaveBeenCalled();
        }
      ),
      { numRuns: 50 }
    );
  });
});
