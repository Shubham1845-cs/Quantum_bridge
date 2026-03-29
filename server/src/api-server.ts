import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { env } from './config/env.js';
import { globalLimiter, healthLimiter } from './middleware/rateLimiter.js';
import { authRouter } from './modules/auth/authRouter.js';

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

// Req 17.4 — Health endpoint with dedicated rate limiter (60 req/min per IP)
app.get('/health', healthLimiter, (_req, res) => {
  res.json({ status: 'ok' });
});

// Auth routes — Req 1.1, 2.1, 17.4
app.use('/auth', authRouter);

// Additional routes wired in subsequent tasks (2.9, 3.5, etc.)

export { app };
export default app;
