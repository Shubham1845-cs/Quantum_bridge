import { Request, Response, NextFunction } from 'express';
import { ZodSchema, ZodError } from 'zod';

/**
 * Returns middleware that validates `req.body` against the provided Zod schema.
 * Returns 422 Unprocessable Entity with structured error details on violation.
 * (Req 10.7)
 */
export function validateBody<T>(schema: ZodSchema<T>) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const result = schema.safeParse(req.body);

    if (!result.success) {
      const errors = (result.error as ZodError).errors.map((e) => ({
        path: e.path.join('.'),
        message: e.message,
      }));
      res.status(422).json({ error: 'Unprocessable Entity', details: errors });
      return;
    }

    // Replace req.body with the parsed (and coerced) value
    req.body = result.data;
    next();
  };
}
