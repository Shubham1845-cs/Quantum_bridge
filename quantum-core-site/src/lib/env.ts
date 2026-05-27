/**
 * Environment variable validation and access
 */

interface EnvConfig {
  apiUrl: string;
  stripePublicKey: string;
}

function validateEnv(): EnvConfig {
  const apiUrl = import.meta.env.VITE_API_URL || '/api';
  const stripePublicKey = import.meta.env.VITE_STRIPE_PUBLIC_KEY || '';

  // Warn if Stripe key is missing (not critical for development)
  if (!stripePublicKey && import.meta.env.PROD) {
    console.warn('VITE_STRIPE_PUBLIC_KEY is not set. Billing features will not work.');
  }

  return {
    apiUrl,
    stripePublicKey,
  };
}

export const env = validateEnv();
