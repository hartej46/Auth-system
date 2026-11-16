import { Request, Response } from "express";
import AppError from "../utils/error.ts";
import { JwtTokenPayload, User } from "../models/User.model.ts";
import { verifyAccessToken, verifyRefreshToken } from "../utils/token.ts";
import { csrfTokenOptions, refreshTokenOption } from "../constant.ts";

export const getSessionIdFromRequest = (req: Request): string => {
    const customReq = req as typeof req & { sessionId?: string };
    if (customReq.sessionId) {
        return customReq.sessionId;
    }

    const authHeader = req.headers.authorization;
    const accessToken =
        authHeader && authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : undefined;

    if (accessToken) {
        try {
            const payload = verifyAccessToken(accessToken) as JwtTokenPayload;
            if (payload.sessionId) return payload.sessionId;
        } catch {}
    }

    const refreshToken = req.cookies?.refreshToken;
    if (refreshToken) {
        try {
            const payload = verifyRefreshToken(refreshToken) as JwtTokenPayload;
            if (payload.sessionId) return payload.sessionId;
        } catch {}
    }

    throw new AppError("Authentication session is required", 401);
};

export const clearAuthenticationCookies = (res: Response): void => {
    res.clearCookie("csrfToken", csrfTokenOptions);
    res.clearCookie("refreshToken", refreshTokenOption);
};

export const getAuthenticatedUser = (req: Request): User => {
    const user = (req as typeof req & { user?: User }).user;
    if (!user) throw new AppError("Authentication is required", 401);
    return user;
};
