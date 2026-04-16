/**
 * Property 34: SIGTERM Drain Correctness
 * Feature: quantum-bridge, Property 34
 *
 * Requirements: 15.9, 15.10
 *
 * Verifies that setupGracefulShutdown:
 *   - calls server.close() on SIGTERM
 *   - sets Connection: close on in-flight requests during drain
 *   - is idempotent (multiple SIGTERM signals don't double-close)
 *   - schedules a force-kill timeout of 10 seconds
 *   - logs the shutdown lifecycle events
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import * as fc from 'fast-check';
import http from 'node:http';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

vi.mock('./utils/logger.js', () => ({
  default: { info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() },
}));

import logger from './utils/logger.js';
import { setupGracefulShutdown } from './utils/gracefulShutdown.js';

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a minimal mock http.Server with spy-able close() and event emitter. */
function makeMockServer() {
  const listeners: Record<string, ((...args: unknown[]) => void)[]> = {};
  const closeCb: (() => void)[] = [];

  const server = {
    close: vi.fn((cb?: () => void) => {
      if (cb) closeCb.push(cb);
    }),
    on: vi.fn((event: string, handler: (...args: unknown[]) => void) => {
      listeners[event] = listeners[event] ?? [];
      listeners[event].push(handler);
    }),
    // Helpers for test control
    _emit: (event: string, ...args: unknown[]) => {
      (listeners[event] ?? []).forEach((h) => h(...args));
    },
    _drainComplete: () => {
      closeCb.forEach((cb) => cb());
    },
  } as unknown as http.Server & {
    _emit: (event: string, ...args: unknown[]) => void;
    _drainComplete: () => void;
  };

  return server;
}

/** Capture process.on listeners so we can trigger SIGTERM in tests. */
function captureProcessListeners() {
  const handlers: ((...args: unknown[]) => void)[] = [];
  const spy = vi.spyOn(process, 'on').mockImplementation((event, handler) => {
    if (event === 'SIGTERM') handlers.push(handler as (...args: unknown[]) => void);
    return process;
  });
  return { handlers, spy };
}

/** Trigger all captured SIGTERM handlers. */
function emitSIGTERM(handlers: ((...args: unknown[]) => void)[]) {
  handlers.forEach((h) => h());
}

// ---------------------------------------------------------------------------
// Property 34: SIGTERM Drain Correctness
// Feature: quantum-bridge, Property 34
// ---------------------------------------------------------------------------

describe('Property 34: SIGTERM Drain Correctness (Req 15.9, 15.10)', () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.clearAllMocks();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  // -------------------------------------------------------------------------
  // P34-a: server.close() is always called on SIGTERM
  // -------------------------------------------------------------------------
  it('server.close() is called exactly once when SIGTERM is received', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 32 }), // label
        (label) => {
          vi.clearAllMocks();
          const server = makeMockServer();
          const { handlers, spy } = captureProcessListeners();

          setupGracefulShutdown(server, label);
          emitSIGTERM(handlers);

          expect(server.close).toHaveBeenCalledTimes(1);
          spy.mockRestore();
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P34-b: SIGTERM handler is idempotent — multiple signals don't double-close
  // -------------------------------------------------------------------------
  it('multiple SIGTERM signals only trigger server.close() once (idempotent)', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 32 }),
        fc.integer({ min: 2, max: 10 }), // number of SIGTERM signals
        (label, signalCount) => {
          vi.clearAllMocks();
          const server = makeMockServer();
          const { handlers, spy } = captureProcessListeners();

          setupGracefulShutdown(server, label);

          // Fire SIGTERM multiple times
          for (let i = 0; i < signalCount; i++) {
            emitSIGTERM(handlers);
          }

          // server.close() must only be called once regardless of signal count
          expect(server.close).toHaveBeenCalledTimes(1);
          spy.mockRestore();
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P34-c: Connection: close is set on requests arriving during drain
  // -------------------------------------------------------------------------
  it('requests arriving during drain window receive Connection: close header', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 32 }),
        (label) => {
          vi.clearAllMocks();
          const server = makeMockServer();
          const { handlers, spy } = captureProcessListeners();

          setupGracefulShutdown(server, label);

          // Trigger SIGTERM — now in drain mode
          emitSIGTERM(handlers);

          // Simulate a request arriving during drain
          const mockRes = { setHeader: vi.fn() };
          (server as unknown as { _emit: (e: string, ...a: unknown[]) => void })
            ._emit('request', {}, mockRes);

          expect(mockRes.setHeader).toHaveBeenCalledWith('Connection', 'close');
          spy.mockRestore();
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P34-d: Requests arriving BEFORE SIGTERM do NOT get Connection: close
  // -------------------------------------------------------------------------
  it('requests arriving before SIGTERM do not receive Connection: close', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 32 }),
        (label) => {
          vi.clearAllMocks();
          const server = makeMockServer();
          const { handlers, spy } = captureProcessListeners();

          setupGracefulShutdown(server, label);

          // Request arrives BEFORE SIGTERM
          const mockRes = { setHeader: vi.fn() };
          (server as unknown as { _emit: (e: string, ...a: unknown[]) => void })
            ._emit('request', {}, mockRes);

          expect(mockRes.setHeader).not.toHaveBeenCalledWith('Connection', 'close');

          // Now trigger SIGTERM — should not affect the already-handled request
          emitSIGTERM(handlers);
          expect(mockRes.setHeader).not.toHaveBeenCalledWith('Connection', 'close');

          spy.mockRestore();
        }
      ),
      { numRuns: 30 }
    );
  });

  // -------------------------------------------------------------------------
  // P34-e: Force-kill timeout is scheduled at exactly 10 000 ms
  // -------------------------------------------------------------------------
  it('a force-kill setTimeout of 10 000 ms is scheduled on SIGTERM', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 32 }),
        (label) => {
          vi.clearAllMocks();
          const setTimeoutSpy = vi.spyOn(global, 'setTimeout');
          const server = makeMockServer();
          const { handlers, spy } = captureProcessListeners();

          setupGracefulShutdown(server, label);
          emitSIGTERM(handlers);

          // At least one setTimeout call must be for 10 000 ms
          const timeoutCalls = setTimeoutSpy.mock.calls.map((c) => c[1]);
          expect(timeoutCalls).toContain(10_000);

          spy.mockRestore();
          setTimeoutSpy.mockRestore();
        }
      ),
      { numRuns: 20 }
    );
  });

  // -------------------------------------------------------------------------
  // P34-f: Shutdown lifecycle is logged with the correct label
  // -------------------------------------------------------------------------
  it('SIGTERM receipt is logged with the server label', () => {
    fc.assert(
      fc.property(
        fc.string({ minLength: 1, maxLength: 32 }).filter((s) => s.trim().length > 0),
        (label) => {
          vi.clearAllMocks();
          const server = makeMockServer();
          const { handlers, spy } = captureProcessListeners();

          setupGracefulShutdown(server, label);
          emitSIGTERM(handlers);

          // logger.info must have been called with a message containing the label
          const infoCalls = vi.mocked(logger.info).mock.calls;
          const hasLabelLog = infoCalls.some(([msg]) =>
            typeof msg === 'string' && msg.includes(label)
          );
          expect(hasLabelLog).toBe(true);

          spy.mockRestore();
        }
      ),
      { numRuns: 30 }
    );
  });
});
