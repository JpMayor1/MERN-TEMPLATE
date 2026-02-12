// libraries
import { Request, Response } from "express";
import geoip from "geoip-lite";
import { UAParser } from "ua-parser-js";
import { v4 as uuid } from "uuid";

// Models
import Account from "@/models/account/account.model";

// Services
import {
  findAccountS,
  pullExpiredSessionsS,
  pushSessionS,
  registerS,
} from "@/services/auth/auth.service";

// Utils
import { SessionType } from "@/types/models/account.type";
import { compareHashed, hashValue } from "@/utils/bcrypt/bcrypt.util";
import {
  clearRefreshCookie,
  REFRESH_COOKIE_NAME,
  setRefreshCookie,
} from "@/utils/cookie/cookie.util";
import { AppError } from "@/utils/error/app-error.util";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} from "@/utils/jwt/jwt.util";
import { buildSession } from "@/utils/session/session.util";

export const register = async (req: Request, res: Response) => {
  // Get the data from request body
  const { name, email, password } = req.body;

  // Validate the data
  if (!name) throw new AppError("Name is required.", 400);
  if (!email) throw new AppError("Email is required.", 400);
  if (!password) throw new AppError("Password is required.", 400);

  // Check if the email already exist
  if (await findAccountS({ email }))
    throw new AppError("Email already exist.", 409);

  // Create the account
  const account = await registerS({
    name,
    email,
    password: await hashValue(password),
  });
  if (!account) throw new AppError("Failed to create account.", 500);

  // Get uuid
  const sid = uuid();

  // Generate tokens
  const sub = String(account._id);
  const accessToken = signAccessToken(sub);
  const refreshToken = signRefreshToken(sub, sid);

  // Build session and save it in database
  const session = await buildSession(req, refreshToken, sid);

  // Push the session to database
  const updated = await pushSessionS(String(account._id), session);
  if (!updated) throw new AppError("Account not found.", 404);

  // Set the refresh token in cookie
  setRefreshCookie(res, refreshToken);

  // Send response
  return res.status(200).json({
    message: "Account registered successfully.",
    accessToken,
  });
};

export const login = async (req: Request, res: Response) => {
  // Get the data from request body
  const { email, password } = req.body;

  // Validate the data
  if (!email) throw new AppError("Email is required.", 400);
  if (!password) throw new AppError("Password is required.", 400);

  // Find the account by email
  const account = await findAccountS({ email });
  if (!account) throw new AppError("Account not found.", 404);

  // Compare the password with the hashed password in database
  const ok = await compareHashed(password, account.password);
  if (!ok) throw new AppError("Incorrect password.", 400);

  // Get uuid
  const sid = uuid();

  // Generate tokens
  const sub = String(account._id);
  const accessToken = signAccessToken(sub);
  const refreshToken = signRefreshToken(sub, sid);

  // Build session and save it in database
  const session = await buildSession(req, refreshToken, sid);

  // Push the session to database
  const updated = await pushSessionS(String(account._id), session);
  if (!updated) throw new AppError("Account not found.", 404);

  // Set the refresh token in cookie
  setRefreshCookie(res, refreshToken);

  // Send response
  return res.status(200).json({
    message: "Login successfully.",
    accessToken,
  });
};

export const logout = async (req: Request, res: Response) => {
  // Get the refresh token from cookie
  const token = req.cookies?.[REFRESH_COOKIE_NAME];

  // Revoke the refresh token by removing the session from database
  if (token) {
    try {
      const payload = verifyRefreshToken(token) as { sub: string; sid: string };

      // revoke ONLY this session (preferred)
      await Account.updateOne(
        { _id: payload.sub },
        { $pull: { sessions: { sid: payload.sid } } },
      );
    } catch (err) {
      // log only in development
      if (process.env.NODE_ENV !== "production")
        console.error("Logout verify failed:", err);
    }
  }

  // Clear the refresh token cookie
  clearRefreshCookie(res);

  // Send response
  return res.status(200).json({ message: "Logged out successfully." });
};

export const refresh = async (req: Request, res: Response) => {
  const token = req.cookies?.[REFRESH_COOKIE_NAME];
  if (!token) throw new AppError("Missing refresh token.", 401);

  let payload: { sub: string; sid: string };
  try {
    payload = verifyRefreshToken(token) as { sub: string; sid: string };
  } catch {
    // Invalid/expired JWT => clear cookie
    clearRefreshCookie(res);
    throw new AppError("Invalid refresh token.", 401);
  }

  // Cleanup expired sessions (so they don't accumulate)
  await pullExpiredSessionsS(payload.sub);

  // Fetch account with sessions
  const account = await Account.findById(payload.sub)
    .select("+sessions.token")
    .exec();
  if (!account) {
    clearRefreshCookie(res);
    throw new AppError("Unauthorized.", 401);
  }

  // Find session for this device (sid)
  const session = account.sessions?.find(
    (s: SessionType) => s.sid === payload.sid,
  );
  if (!session) {
    clearRefreshCookie(res);
    throw new AppError("Session not found. Please login again.", 401);
  }

  // Extra safety: if DB says expired, revoke now (even if JWT not expired)
  if (session.expiresAt && new Date(session.expiresAt).getTime() < Date.now()) {
    await Account.updateOne(
      { _id: payload.sub },
      { $pull: { sessions: { sid: payload.sid } } },
    ).exec();

    clearRefreshCookie(res);
    throw new AppError("Session expired. Please login again.", 401);
  }

  // Verify token matches stored hashed token (prevents cookie theft reuse)
  const ok = await compareHashed(token, session.token);
  if (!ok) {
    // Token mismatch: could be stolen/rotated/reused. Kick this session.
    await Account.updateOne(
      { _id: payload.sub },
      { $pull: { sessions: { sid: payload.sid } } },
    ).exec();

    clearRefreshCookie(res);
    throw new AppError("Refresh token mismatch. Please login again.", 401);
  }

  // Rotate refresh token (same sid) + issue new access token
  const newAccessToken = signAccessToken(payload.sub);
  const newRefreshToken = signRefreshToken(payload.sub, payload.sid);
  const newHashedRefresh = await hashValue(newRefreshToken);

  // Optional: update metadata on refresh
  const ip = req.ip;
  const geo = ip ? (geoip.lookup(ip) ?? undefined) : undefined;
  const uaString = req.get("user-agent") ?? "";
  const userAgent = new UAParser(uaString).getResult();

  await Account.updateOne(
    { _id: payload.sub, "sessions.sid": payload.sid },
    {
      $set: {
        "sessions.$.token": newHashedRefresh,
        "sessions.$.expiresAt": new Date(Date.now() + 15 * 24 * 60 * 60 * 1000),
        "sessions.$.ip": ip,
        "sessions.$.geo": geo,
        "sessions.$.userAgent": userAgent,
      },
    },
  ).exec();

  // Send new refresh cookie + return new access token
  setRefreshCookie(res, newRefreshToken);

  return res.status(200).json({
    message: "Token refreshed.",
    accessToken: newAccessToken,
  });
};
