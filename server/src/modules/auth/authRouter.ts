import { Router, Request, Response } from 'express';
import { z } from 'zod';
import { validateBody } from '../../middleware/validateBody.js';
import {
  register,
  verifyEmail,
  resendVerification,
  login,
  refresh,
  logout,
  ConflictError,
  GoneError,
  UnauthorizedError,
  ForbiddenError,
} from './authService.js';

const router = Router();

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const resendSchema = z.object({
  email: z.string().email(),
});

function handleError(err: unknown, res: Response): void {
  if (
    err instanceof ConflictError ||
    err instanceof GoneError ||
    err instanceof UnauthorizedError ||
    err instanceof ForbiddenError
  ) {
    res.status(err.statusCode).json({ error: err.message });
    return;
  }
  res.status(500).json({ error: 'Internal server error' });
}

// POST /auth/register — Req 1.1, 1.2
router.post('/register', validateBody(registerSchema), async (req: Request, res: Response) => {
  try {
    const { userId } = await register(req.body.email, req.body.password);
    res.status(201).json({ userId });
  } catch (err) {
    handleError(err, res);
  }
});

// POST /auth/login — Req 1.4, 2.1
router.post('/login', validateBody(loginSchema), async (req: Request, res: Response) => {
  try {
    const { accessToken, refreshToken } = await login(req.body.email, req.body.password);
    // Req 1.7 — refresh token in httpOnly cookie only, never in response body
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });
    res.json({ accessToken });
  } catch (err) {
    handleError(err, res);
  }
});

// POST /auth/logout — Req 2.4
router.post('/logout', async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies?.refreshToken as string | undefined;
    if (refreshToken) {
      await logout(refreshToken);
    }
    res.clearCookie('refreshToken');
    res.status(204).send();
  } catch (err) {
    handleError(err, res);
  }
});

// POST /auth/refresh — Req 2.2, 2.6
router.post('/refresh', async (req: Request, res: Response) => {
  try {
    const refreshToken = req.cookies?.refreshToken as string | undefined;
    if (!refreshToken) {
      res.status(401).json({ error: 'No refresh token provided' });
      return;
    }
    const { accessToken, refreshToken: newRefreshToken } = await refresh(refreshToken);
    res.cookie('refreshToken', newRefreshToken, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    res.json({ accessToken });
  } catch (err) {
    handleError(err, res);
  }
});

// GET /auth/verify-email — Req 1.3, 1.5
router.get('/verify-email', async (req: Request, res: Response) => {
  try {
    const token = req.query.token as string | undefined;
    if (!token) {
      res.status(400).json({ error: 'Missing token' });
      return;
    }
    await verifyEmail(token);
    res.json({ message: 'Email verified successfully' });
  } catch (err) {
    handleError(err, res);
  }
});

// POST /auth/resend-verification — Req 1.5
router.post('/resend-verification', validateBody(resendSchema), async (req: Request, res: Response) => {
  try {
    await resendVerification(req.body.email);
    // Always 200 — do not reveal whether email exists
    res.json({ message: 'If an unverified account exists, a new verification email has been sent.' });
  } catch (err) {
    handleError(err, res);
  }
});

export { router as authRouter };
