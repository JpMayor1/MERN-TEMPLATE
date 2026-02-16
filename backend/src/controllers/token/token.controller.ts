// Labraries
import { Request, Response } from "express";
import geoip from "geoip-lite";
import { UAParser } from "ua-parser-js";

// Types
import { SessionType } from "@/types/models/account.type";

// Models
import Account from "@/models/account/account.model";

// Service
import { pullExpiredSessionsS } from "@/services/auth/auth.service";

// Utils
import { compareHashed, hashValue } from "@/utils/bcrypt/bcrypt.util";
import {
  clearRefreshCookie,
  REFRESH_COOKIE_NAME,
  setRefreshCookie,
} from "@/utils/cookie/cookie.util";
import {
  signAccessToken,
  signRefreshToken,
  verifyRefreshToken,
} from "@/utils/jwt/jwt.util";

export const refreshToken = async (req: Request, res: Response) => {
  const ok = (message: string, accessToken: string) =>
    res.status(200).json({ message, accessToken });

  const fail = (message: string) =>
    res.status(200).json({ message, accessToken: null });

  const token = req.cookies?.[REFRESH_COOKIE_NAME];
  if (!token) return fail("Missing refresh token.");

  let payload: { sub: string; sid: string };

  try {
    payload = verifyRefreshToken(token) as { sub: string; sid: string };
  } catch {
    clearRefreshCookie(res);
    return fail("Invalid refresh token.");
  }

  await pullExpiredSessionsS(payload.sub);

  const account = await Account.findById(payload.sub)
    .select("+sessions.token")
    .exec();

  if (!account) {
    clearRefreshCookie(res);
    return fail("Unauthorized.");
  }

  const session = account.sessions?.find(
    (s: SessionType) => s.sid === payload.sid,
  );

  if (!session) {
    clearRefreshCookie(res);
    return fail("Session not found. Please login again.");
  }

  if (session.expiresAt && new Date(session.expiresAt).getTime() < Date.now()) {
    await Account.updateOne(
      { _id: payload.sub },
      { $pull: { sessions: { sid: payload.sid } } },
    ).exec();

    clearRefreshCookie(res);
    return fail("Session expired. Please login again.");
  }

  const matches = await compareHashed(token, session.token);

  if (!matches) {
    await Account.updateOne(
      { _id: payload.sub },
      { $pull: { sessions: { sid: payload.sid } } },
    ).exec();

    clearRefreshCookie(res);
    return fail("Refresh token mismatch. Please login again.");
  }

  const newAccessToken = signAccessToken(payload.sub);
  const newRefreshToken = signRefreshToken(payload.sub, payload.sid);
  const newHashedRefresh = await hashValue(newRefreshToken);

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

  setRefreshCookie(res, newRefreshToken);

  return ok("Token refreshed.", newAccessToken);
};
