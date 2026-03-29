import { Redis } from 'ioredis';
import { env } from './env.js';

/**
 * Main Redis client — used for all regular commands (GET, SET, DEL, PUBLISH, etc.)
 *
 * Upstash Redis is fully compatible with ioredis, so we just point it at REDIS_URL.
 * lazyConnect: true means the connection is established on first command, not at import time.
 */
export const redis = new Redis(env.REDIS_URL, {
  lazyConnect: true,
  maxRetriesPerRequest: 3,
});

redis.on('connect', () => console.info('[Redis] Connected'));
redis.on('error', (err: Error) => console.error('[Redis] Connection error', err));

/**
 * Creates a dedicated subscriber connection for Redis pub/sub.
 *
 * WHY a separate connection?
 * Once a Redis client calls .subscribe(), it enters "subscriber mode" and can
 * no longer issue regular commands (GET, SET, DEL, etc.).  The Proxy_Engine
 * needs to both listen for cache-invalidation events AND issue DEL commands,
 * so it must use two separate connections.
 *
 * Usage (in proxy-server.ts):
 *   const sub = duplicate();
 *   await sub.connect();
 *   await sub.subscribe('endpoint:invalidate', handler);
 */
export function duplicate(): Redis {
  return new Redis(env.REDIS_URL, {
    lazyConnect: true,
    maxRetriesPerRequest: 3,
  });
}
