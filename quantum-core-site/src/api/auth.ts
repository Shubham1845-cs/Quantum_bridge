import apiClient, { setToken } from './client';

export interface LoginResponse {
  accessToken: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
}

export interface RegisterResponse {
  userId: string;
}

/**
 * Converts a raw axios error into a human-readable message.
 * Prefers the backend's `error` field, falls back to status-based messages.
 */
function friendlyAuthError(err: any, context: 'login' | 'register'): string {
  const status: number | undefined = err?.response?.status;
  // Use the backend's own message if it exists and isn't a generic HTTP phrase
  const backendMsg: string | undefined = err?.response?.data?.error || err?.response?.data?.message;

  if (context === 'login') {
    if (status === 401 || status === 400) return 'Incorrect email or password. Please try again.';
    if (status === 403) return 'Your email address has not been verified yet. Check your inbox for the confirmation link.';
    if (status === 429) return 'Too many login attempts. Please wait a moment and try again.';
    if (status === 404) return 'No account found with that email address.';
  }

  if (context === 'register') {
    if (status === 409) return 'An account with this email already exists. Try signing in instead.';
    if (status === 400) return backendMsg || 'Please check your details and try again.';
    if (status === 422) return 'Invalid email address or password format.';
    if (status === 429) return 'Too many requests. Please wait a moment and try again.';
  }

  if (status === 500 || status === 502 || status === 503) {
    return 'Something went wrong on our end. Please try again in a moment.';
  }

  if (!status) {
    return 'Unable to connect. Check your internet connection and try again.';
  }

  // Fall back to a sanitised backend message or a generic one
  return backendMsg || 'Something went wrong. Please try again.';
}

/** POST /auth/register */
export async function register(data: RegisterRequest): Promise<RegisterResponse> {
  try {
    const response = await apiClient.post<RegisterResponse>('/auth/register', data);
    return response.data;
  } catch (err: any) {
    throw new Error(friendlyAuthError(err, 'register'));
  }
}

/** POST /auth/login — stores the access token in memory */
export async function login(email: string, password: string): Promise<void> {
  try {
    const { data } = await apiClient.post<LoginResponse>('/auth/login', {
      email,
      password,
    });
    setToken(data.accessToken);
  } catch (err: any) {
    const friendlyMsg = friendlyAuthError(err, 'login');
    const error = new Error(friendlyMsg) as Error & { statusCode?: number };
    error.statusCode = err?.response?.status;
    throw error;
  }
}

/** POST /auth/logout — clears cookies + in-memory token */
export async function logout(): Promise<void> {
  await apiClient.post('/auth/logout');
  setToken(null);
}

/** POST /auth/refresh — rotates access token via httpOnly cookie */
export async function refresh(): Promise<void> {
  const { data } = await apiClient.post<LoginResponse>('/auth/refresh');
  setToken(data.accessToken);
}

/** GET /auth/verify-email?token={token} */
export async function verifyEmail(token: string): Promise<void> {
  await apiClient.get(`/auth/verify-email?token=${token}`);
}

/** POST /auth/resend-verification */
export async function resendVerification(email: string): Promise<void> {
  await apiClient.post('/auth/resend-verification', { email });
}
