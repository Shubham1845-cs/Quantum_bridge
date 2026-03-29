import rateLimit from 'express-rate-limit';

/**
 * Global management API limiter: 100 req / 15 min per IP
 * Applied to all API_Server management endpoints (Req 2.7, 10.4)
 */
export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests, please try again later.' },
});

/**
 * Health endpoint limiter: 60 req / min per IP
 * Applied to GET /health on both API_Server and Proxy_Engine (Req 17.4, 17.5)
 */
export const healthLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many health check requests.' },
});
