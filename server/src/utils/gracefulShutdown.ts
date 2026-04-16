import http from 'node:http';
import logger from './logger.js';

/**
 * Attach a SIGTERM handler that:
 *   1. Stops accepting new connections immediately.
 *   2. Allows in-flight requests up to 10 seconds to complete.
 *   3. Exits cleanly (code 0) once all connections drain.
 *   4. Force-kills (code 1) after the 10-second drain window.
 *
 * Requirements: 15.9 (API_Server), 15.10 (Proxy_Engine)
 */
export function setupGracefulShutdown(server: http.Server, label: string): void {
  let isShuttingDown = false;

  // Reject new requests during drain with Connection: close
  server.on('request', (_req, res) => {
    if (isShuttingDown) {
      res.setHeader('Connection', 'close');
    }
  });

  process.on('SIGTERM', () => {
    if (isShuttingDown) return; // idempotent
    isShuttingDown = true;

    logger.info(`${label}: SIGTERM received — starting graceful shutdown`);

    // Stop accepting new connections; callback fires when all existing
    // connections have closed naturally.
    server.close(() => {
      logger.info(`${label}: all connections closed — exiting cleanly`);
      process.exit(0);
    });

    // Force-kill after 10 s so the process never hangs indefinitely.
    // Req 15.9/15.10: requests still active after 10 s are terminated and logged.
    const forceKill = setTimeout(() => {
      logger.warn(`${label}: drain window exceeded (10 s) — forcing shutdown`);
      process.exit(1);
    }, 10_000);

    // Don't let this timer keep the event loop alive if everything drains early.
    if (forceKill.unref) forceKill.unref();
  });
}
