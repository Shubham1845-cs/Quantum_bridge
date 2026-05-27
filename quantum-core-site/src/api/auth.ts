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

/** POST /auth/register */
export async function register(data: RegisterRequest): Promise<RegisterResponse> {
  const response = await apiClient.post<RegisterResponse>('/auth/register', data);
  return response.data;
}

/** POST /auth/login — stores the access token in memory */
export async function login(email: string, password: string): Promise<void> {
  const { data } = await apiClient.post<LoginResponse>('/auth/login', {
    email,
    password,
  });
  setToken(data.accessToken);
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
