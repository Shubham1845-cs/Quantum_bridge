import { z } from 'zod';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  PORT: z.coerce.number().default(3000),
  PROXY_PORT: z.coerce.number().default(8080),
  MONGO_URI: z.string().url('MONGO_URI must be a valid URL'),
  JWT_SECRET: z.string().min(32, 'JWT_SECRET must be at least 32 characters'),
  JWT_REFRESH_SECRET: z.string().min(32, 'JWT_REFRESH_SECRET must be at least 32 characters'),
  REDIS_URL: z.string().url('REDIS_URL must be a valid URL'),
  ALLOWED_ORIGIN: z.string().url('ALLOWED_ORIGIN must be a valid URL'),
  STRIPE_SECRET_KEY: z.string().startsWith('sk_', 'STRIPE_SECRET_KEY must start with sk_'),
  STRIPE_WEBHOOK_SECRET: z.string().startsWith('whsec_', 'STRIPE_WEBHOOK_SECRET must start with whsec_'),
  RESEND_API_KEY: z.string().min(1, 'RESEND_API_KEY is required'),
  SENTRY_DSN: z.string().url('SENTRY_DSN must be a valid URL'),
  PBKDF2_GLOBAL_PEPPER: z.string().min(32, 'PBKDF2_GLOBAL_PEPPER must be at least 32 characters'),
});

function parseEnv() {
  const result = envSchema.safeParse(process.env);

  if (!result.success) {
    const errors = result.error.errors
      .map((e) => `  - ${e.path.join('.')}: ${e.message}`)
      .join('\n');
    console.error(`[QuantumBridge] Environment configuration error:\n${errors}`);
    process.exit(1);
  }

  return result.data;
}

export const env = parseEnv();
export type Env = z.infer<typeof envSchema>;
