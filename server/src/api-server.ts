import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import mongoose from 'mongoose';
import { env } from './config/env.js';
import { globalLimiter, healthLimiter } from './middleware/rateLimiter.js';
import { redis } from './config/redis.js';
import { authRouter } from './modules/auth/authRouter.js';
import { orgRouter } from './modules/organization/orgRouter.js';
import { endpointRouter } from './modules/endpoint/endpointRouter.js';
import { analyticsRouter } from './modules/analytics/analyticsRouter.js';
import { setupGracefulShutdown } from './utils/gracefulShutdown.js';
import { connectWithRetry } from './config/database.js';
import { keyVaultService } from './modules/keyVault/keyVaultService.js';
import logger from './utils/logger.js';

const app = express();

// Req 10.1 — Security headers (X-Content-Type-Options, X-Frame-Options, HSTS, CSP, etc.)
app.use(helmet());

// Req 10.2 — Restrict CORS to ALLOWED_ORIGIN; reject other origins with 403
app.use(
  cors({
    origin: (origin, callback) => {
      // Allow requests with no origin (e.g. server-to-server) only in non-production
      if (!origin) {
        if (env.NODE_ENV !== 'production') return callback(null, true);
        return callback(Object.assign(new Error('Forbidden'), { status: 403 }));
      }
      if (origin === env.ALLOWED_ORIGIN) {
        return callback(null, true);
      }
      return callback(Object.assign(new Error('Forbidden'), { status: 403 }));
    },
    credentials: true,
  })
);

// Req 10.3 — Reject request bodies larger than 10KB with 413
app.use(express.json({ limit: '10kb' }));
app.use(express.urlencoded({ extended: false, limit: '10kb' }));

// Cookie parser — required for httpOnly refresh token cookies (Req 1.7, 2.1)
app.use(cookieParser());

// Req 10.4 — Global rate limit: 100 req / 15 min per IP on all management endpoints
app.use(globalLimiter);

// Req 17.4, 17.6 — Health endpoint: check DB + Redis connectivity; 503 on failure
app.get('/health', healthLimiter, async (_req, res) => {
  const dbOk = mongoose.connection.readyState === 1; // 1 = connected

  let redisOk = false;
  try {
    await redis.ping();
    redisOk = true;
  } catch {
    redisOk = false;
  }

  const healthy = dbOk && redisOk;
  res.status(healthy ? 200 : 503).json({
    status: healthy ? 'ok' : 'degraded',
    db: dbOk ? 'connected' : 'disconnected',
    redis: redisOk ? 'connected' : 'disconnected',
  });
});

// Auth routes — Req 1.1, 2.1, 17.4
app.use('/auth', authRouter);

// Org CRUD + member management + key routes — Req 3.1, 4.6, 4.8
app.use('/orgs', orgRouter);

// Endpoint routes — Req 5.1, 5.2, 5.7
app.use('/orgs/:orgId/endpoints', endpointRouter);

// Analytics — ProxyLog queries, export, summary, timeseries (Req 7.1, 7.2, 7.4, 7.6)
app.use('/orgs/:orgId/logs', analyticsRouter);
app.use('/orgs/:orgId/analytics', analyticsRouter);

export { app };
export default app;

// ---------------------------------------------------------------------------
// Server startup (only when run directly, not during tests)
// ---------------------------------------------------------------------------

if (process.env.NODE_ENV !== 'test') {
  async function start(): Promise<void> {
    await connectWithRetry();
    keyVaultService.runRotationScheduler();
    const server = app.listen(env.PORT, () => {
      logger.info(`API_Server listening on port ${env.PORT}`);
    });
    setupGracefulShutdown(server, 'API_Server');
  }

  start().catch((err) => {
    logger.error('API_Server failed to start', { err });
    process.exit(1);
  });
}
