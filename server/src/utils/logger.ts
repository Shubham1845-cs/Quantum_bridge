import winston from 'winston';
import Transport from 'winston-transport';
import * as Sentry from '@sentry/node';
import { env } from '../config/env.js';

// ---------------------------------------------------------------------------
// Sentry initialisation
// ---------------------------------------------------------------------------
// Sentry must be initialised once, as early as possible, before any errors
// can occur.  We do it here so importing `logger` is enough to activate it.
Sentry.init({
  dsn: env.SENTRY_DSN,
  environment: env.NODE_ENV,
  // Capture 100 % of transactions in dev/test; tune down in production.
  tracesSampleRate: env.NODE_ENV === 'production' ? 0.1 : 1.0,
});

// ---------------------------------------------------------------------------
// Custom Winston transport → Sentry
// ---------------------------------------------------------------------------
// A "transport" is just a destination for log entries.
// This one forwards every `error`-level log to Sentry so the team gets
// alerted without having to manually check logs.
//
// SECURITY: we never pass raw Error objects that might contain key material.
// We only forward the sanitised `message` string and safe `meta` fields.
class SentryTransport extends Transport {
  log(info: winston.Logform.TransformableInfo, callback: () => void): void {
    setImmediate(() => this.emit('logged', info));

    if (info.level === 'error') {
      const err = info instanceof Error ? info : new Error(String(info.message));
      Sentry.captureException(err, {
        // Attach any extra context that was passed to logger.error(msg, meta)
        extra: info.meta as Record<string, unknown>,
      });
    }

    callback();
  }
}

// ---------------------------------------------------------------------------
// Winston logger
// ---------------------------------------------------------------------------
// Transports:
//   1. Console  — human-readable in dev, JSON in production
//   2. Sentry   — error-level only
//
// Format pipeline (applied in order):
//   timestamp  → adds `timestamp` field
//   errors     → ensures Error stack traces are serialised
//   json       → serialises the whole entry as a single JSON line
const logger = winston.createLogger({
  // In test mode silence all output so test output stays clean.
  silent: env.NODE_ENV === 'test',

  // Minimum level to process.  `debug` in dev, `info` in production.
  level: env.NODE_ENV === 'production' ? 'info' : 'debug',

  format: winston.format.combine(
    winston.format.timestamp(),             // adds { timestamp: "2026-..." }
    winston.format.errors({ stack: true }), // serialise Error.stack
    winston.format.json(),                  // output as a single JSON line
  ),

  transports: [
    // Console transport — always present
    new winston.transports.Console({
      // In development, pretty-print with colours for readability.
      // In production, keep raw JSON so log aggregators can parse it.
      format:
        env.NODE_ENV !== 'production'
          ? winston.format.combine(
              winston.format.colorize(),
              winston.format.simple(), // "info: message {meta}"
            )
          : undefined, // falls back to the logger-level JSON format above
    }),

    // Sentry transport — error level only
    new SentryTransport({ level: 'error' }),
  ],
});

export default logger;
