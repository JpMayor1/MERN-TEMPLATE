import { AppError } from "@/utils/error/app-error.util";
import { verifyAccessToken } from "@/utils/jwt/jwt.util";
import type { NextFunction, Request, Response } from "express";

// Authenticated user payload
type AuthUser = {
  sub: string;
};

// Request extended with auth user
export interface AuthedRequest extends Request {
  user?: AuthUser;
}

// Validates access token from Authorization header
export const requireAccessToken = (
  req: AuthedRequest,
  _res: Response,
  next: NextFunction,
) => {
  // Read Authorization header
  const auth = req.headers.authorization;

  // Ensure Bearer token exists
  if (!auth || !auth.startsWith("Bearer ")) {
    return next(new AppError("Unauthorized: Missing access token.", 401));
  }

  // Extract token
  const token = auth.slice("Bearer ".length).trim();

  try {
    // Verify token signature and expiry
    const payload = verifyAccessToken(token) as { sub: string };

    // Validate payload
    if (!payload?.sub) {
      return next(new AppError("Unauthorized: Invalid access token.", 401));
    }

    // Attach user to request
    req.user = { sub: payload.sub };

    // Continue request
    return next();
  } catch {
    // Handle invalid or expired token
    return next(
      new AppError("Unauthorized: Invalid or expired access token.", 401),
    );
  }
};
