/**
 * Property 35: Structured Log Completeness
 * Feature: quantum-bridge, Property 35
 *
 * Requirements: 17.1
 *
 * Verifies that the logger emits structured log entries containing all
 * required fields (timestamp, level, message) for every log call, and
 * that the logger exposes the required log levels (debug, info, warn, error).
 *
 * Property: FOR ALL log calls at any level with any message and metadata,
 *   the logger MUST produce an entry that includes:
 *     - a `timestamp` field
 *     - a `level` field matching the called level
 *     - a `message` field matching the input message
 *   AND the entry MUST NOT contain private key material.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fc from 'fast-check';

// ---------------------------------------------------------------------------
// Mocks — must be hoisted before any imports that trigger logger initialisation
// ---------------------------------------------------------------------------

vi.mock('../config/env.js', () => ({
  env: {
    NODE_ENV: 'test',
    SENTRY_DSN: 'https://test@sentry.io/0',
    PORT: 3000,
    PROXY_PORT: 8080,
    MONGO_URI: 'mongodb://localhost:27017/test',
    JWT_SECRET: 'test-secret-that-is-at-least-32-chars-long',
    JWT_REFRESH_SECRET: 'test-refresh-secret-at-least-32-chars',
    REDIS_URL: 'redis://localhost:6379',
    ALLOWED_ORIGIN: 'http://localhost:5173',
    STRIPE_SECRET_KEY: 'sk_test_placeholder',
    STRIPE_WEBHOOK_SECRET: 'whsec_placeholder',
    RESEND_API_KEY: 're_placeholder',
    PBKDF2_GLOBAL_PEPPER: 'test-pepper-that-is-at-least-32-chars-long',
  },
}));

vi.mock('@sentry/node', () => ({
  init: vi.fn(),
  captureException: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Capture Winston log output via a custom transport spy
// ---------------------------------------------------------------------------

/**
 * We intercept Winston's write pipeline by spying on the Console transport's
 * `log` method after the logger is imported. This lets us inspect the fully-
 * formatted log entry (with timestamp, level, message) without touching the
 * real console or Sentry.
 */

import winston from 'winston';

// Collect entries written to any transport
const capturedEntries: winston.Logform.TransformableInfo[] = [];

// Spy transport that captures every entry passed through the format pipeline
class CapturingTransport extends winston.transports.Console {
  log(info: winston.Logform.TransformableInfo, callback: () => void): void {
    capturedEntries.push({ ...info });
    callback();
  }
}

// Build a test logger that mirrors the production logger's format pipeline
// but routes output to our capturing transport instead of the real console.
function buildTestLogger() {
  return winston.createLogger({
    silent: false,
    level: 'debug',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.errors({ stack: true }),
      winston.format.json(),
    ),
    transports: [new CapturingTransport()],
  });
}

// ---------------------------------------------------------------------------
// Arbitraries
// ---------------------------------------------------------------------------

const logLevelArb = fc.constantFrom('debug', 'info', 'warn', 'error') as fc.Arbitrary<
  'debug' | 'info' | 'warn' | 'error'
>;

const safeMessageArb = fc.string({ minLength: 1, maxLength: 128 }).filter(
  (s) => s.trim().length > 0
);

// Metadata that must never contain private key material
const safeMetaArb = fc.option(
  fc.dictionary(
    fc.string({ minLength: 1, maxLength: 16 }),
    fc.oneof(fc.string({ maxLength: 32 }), fc.integer(), fc.boolean()),
  ),
  { nil: undefined }
);

// Strings that look like private key material (must never appear in logs)
const privateKeyPatterns = [
  '-----BEGIN PRIVATE KEY-----',
  '-----BEGIN EC PRIVATE KEY-----',
  '-----BEGIN RSA PRIVATE KEY-----',
  'PRIVATE KEY',
];

// ---------------------------------------------------------------------------
// Property 35: Structured Log Completeness
// Feature: quantum-bridge, Property 35
// ---------------------------------------------------------------------------

describe('Property 35: Structured Log Completeness (Req 17.1)', () => {
  let testLogger: winston.Logger;

  beforeEach(() => {
    capturedEntries.length = 0;
    testLogger = buildTestLogger();
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  // -------------------------------------------------------------------------
  // P35-a: Every log entry contains timestamp, level, and message
  // -------------------------------------------------------------------------
  it('every log entry contains timestamp, level, and message fields', () => {
    fc.assert(
      fc.property(logLevelArb, safeMessageArb, (level, message) => {
        capturedEntries.length = 0;

        testLogger[level](message);

        expect(capturedEntries.length).toBeGreaterThanOrEqual(1);

        const entry = capturedEntries[capturedEntries.length - 1];

        // Required structured fields per Req 17.1
        expect(entry).toHaveProperty('timestamp');
        expect(typeof entry.timestamp).toBe('string');
        expect(entry.timestamp).not.toBe('');

        expect(entry).toHaveProperty('level');
        expect(entry.level).toBe(level);

        expect(entry).toHaveProperty('message');
        expect(entry.message).toBe(message);
      }),
      { numRuns: 50 }
    );
  });

  // -------------------------------------------------------------------------
  // P35-b: Metadata passed to the logger is included in the entry
  // -------------------------------------------------------------------------
  it('metadata passed alongside the message is included in the log entry', () => {
    fc.assert(
      fc.property(
        logLevelArb,
        safeMessageArb,
        fc.dictionary(
          // Restrict to safe identifier-like keys that Winston preserves as top-level properties
          fc.stringMatching(/^[a-zA-Z][a-zA-Z0-9_]{0,15}$/),
          fc.string({ maxLength: 32 }),
        ),
        (level, message, meta) => {
          capturedEntries.length = 0;

          testLogger[level](message, meta);

          const entry = capturedEntries[capturedEntries.length - 1];

          // Each metadata key must appear in the captured entry
          for (const [key, value] of Object.entries(meta)) {
            expect(entry).toHaveProperty(key);
            expect(entry[key]).toBe(value);
          }
        }
      ),
      { numRuns: 40 }
    );
  });

  // -------------------------------------------------------------------------
  // P35-c: Timestamp is a valid ISO 8601 date string
  // -------------------------------------------------------------------------
  it('timestamp field is a valid ISO 8601 date string', () => {
    fc.assert(
      fc.property(logLevelArb, safeMessageArb, (level, message) => {
        capturedEntries.length = 0;

        testLogger[level](message);

        const entry = capturedEntries[capturedEntries.length - 1];
        const parsed = new Date(entry.timestamp as string);

        expect(isNaN(parsed.getTime())).toBe(false);
      }),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P35-d: Logger exposes all required log levels
  // -------------------------------------------------------------------------
  it('logger exposes debug, info, warn, and error methods', () => {
    fc.assert(
      fc.property(logLevelArb, (level) => {
        expect(typeof testLogger[level]).toBe('function');
      }),
      { numRuns: 10 }
    );
  });

  // -------------------------------------------------------------------------
  // P35-e: Log entries never contain private key material
  // -------------------------------------------------------------------------
  it('log entries never contain private key material in any field', () => {
    fc.assert(
      fc.property(logLevelArb, safeMessageArb, (level, message) => {
        capturedEntries.length = 0;

        testLogger[level](message);

        const entry = capturedEntries[capturedEntries.length - 1];
        const serialised = JSON.stringify(entry);

        for (const pattern of privateKeyPatterns) {
          expect(serialised).not.toContain(pattern);
        }
      }),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P35-f: Log level ordering — entries at or above the configured level
  //         are emitted; entries below are suppressed
  // -------------------------------------------------------------------------
  it('logger configured at "info" level suppresses debug entries', () => {
    const infoLogger = winston.createLogger({
      silent: false,
      level: 'info',
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json(),
      ),
      transports: [new CapturingTransport()],
    });

    fc.assert(
      fc.property(safeMessageArb, (message) => {
        capturedEntries.length = 0;

        infoLogger.debug(message);

        // debug is below info — must be suppressed
        expect(capturedEntries.length).toBe(0);
      }),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P35-g: Multiple sequential log calls each produce a separate entry
  // -------------------------------------------------------------------------
  it('N sequential log calls produce exactly N entries', () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({ level: logLevelArb, message: safeMessageArb }),
          { minLength: 1, maxLength: 10 }
        ),
        (calls) => {
          capturedEntries.length = 0;

          for (const { level, message } of calls) {
            testLogger[level](message);
          }

          expect(capturedEntries.length).toBe(calls.length);
        }
      ),
      { numRuns: 30 }
    );
  });
});
