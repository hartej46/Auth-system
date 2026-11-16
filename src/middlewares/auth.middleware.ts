import asyncHandler from "../utils/asyncHandler.ts";
import jwt from "jsonwebtoken";
import { getUserDetailsById } from "../repository/User.repository.ts";
import { JwtTokenPayload, User } from "../models/User.model.ts";
import AppError from "../utils/error.ts";
import { Request } from "express";
import {
    generateAccessToken,
    generateRefreshToken,
    generateCsrfToken,
    isCsrfTokenValid,
} from "../utils/token.ts";
import { getSessionById, updateSessionById } from "../repository/Session.repository.ts";
import { Session } from "../models/Session.model.ts";
import { refreshTokenOption, csrfTokenOptions } from "../constant.ts";
import crypto from "node:crypto";

export interface AuthenticatedRequest extends Request {
    user?: User;
    sessionId?: string;
}

interface TokenVerificationResponse {
    success: boolean;
    message: string;
    user: User | null;
    session?: Session;
}

/**
 * Primary authentication middleware.
 *
 * 1. Validates the Bearer Access Token in the Authorization header.
 * 2. If valid, attaches user to `req.user` and proceeds.
 * 3. If expired (TokenExpiredError), transparently triggers session-based re-authentication:
 *    - Validates Refresh Token (from cookie) and Double-Submit CSRF Token (header vs cookie HMAC).
 *    - Rotates CSRF secret & session expiry in PostgreSQL.
 *    - Issues and attaches a new Access Token in `x-Access-Token` response header.
 *    - Rotates and attaches new Refresh and CSRF cookies.
 *    - Passes control to next middleware smoothly.
 */
export const authentication = asyncHandler(async (req: AuthenticatedRequest, res, next) => {
    const authHeader = req.headers.authorization;
    const accessToken =
        authHeader && authHeader.startsWith("Bearer ") ? authHeader.split(" ")[1] : "";

    let decodedAccessToken: JwtTokenPayload;

    try {
        decodedAccessToken = jwt.verify(
            accessToken,
            process.env.ACCESS_TOKEN_GENERATOR!
        ) as JwtTokenPayload;
    } catch (error: unknown) {
        if (!(error instanceof jwt.TokenExpiredError)) {
            throw new AppError("Invalid or missing access token", 401);
        }

        const csrfHeader = (req.headers["x-csrf-token"] as string) || "";
        const csrfCookie = req.cookies?.csrfToken || "";
        const refreshToken = req.cookies?.refreshToken || "";

        const isTokenValid = await tokenVerification(refreshToken, csrfHeader, csrfCookie);
        if (!isTokenValid.success || !isTokenValid.user || !isTokenValid.session) {
            throw new AppError("Session expired or invalid. Please log in again.", 401);
        }

        const newSecretKey = crypto.randomBytes(32).toString("hex");
        const newExpiryDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

        try {
            const updatedSession = await updateSessionById(
                isTokenValid.session.id,
                isTokenValid.user.id,
                newSecretKey,
                newExpiryDate
            );
            if (!updatedSession) throw new AppError("Session could not be updated", 401);
        } catch {
            throw new AppError("Authentication tokens are invalid", 401);
        }

        const newAccessToken = generateAccessToken(
            isTokenValid.user.id,
            isTokenValid.session.id,
            isTokenValid.user.email,
            isTokenValid.user.name
        );
        const newRefreshToken = generateRefreshToken(
            isTokenValid.user.id,
            isTokenValid.session.id,
            isTokenValid.user.email,
            isTokenValid.user.name
        );
        const newCsrfToken = generateCsrfToken(newRefreshToken, newSecretKey);

        res.setHeader("x-Access-Token", newAccessToken);
        res.cookie("refreshToken", newRefreshToken, refreshTokenOption);
        res.cookie("csrfToken", newCsrfToken, csrfTokenOptions);

        req.user = isTokenValid.user;
        req.sessionId = isTokenValid.session.id;
        return next();
    }

    const user = await getUserDetailsById(decodedAccessToken.userId);
    if (!user) {
        throw new AppError("User account not found", 404);
    }

    req.user = user;
    req.sessionId = decodedAccessToken.sessionId;
    return next();
});

export const tokenVerification = async (
    token: string,
    csrfHeader: string,
    csrfCookie: string
): Promise<TokenVerificationResponse> => {
    let decodedRefreshToken: JwtTokenPayload;

    try {
        decodedRefreshToken = jwt.verify(
            token,
            process.env.REFRESH_TOKEN_GENERATOR!
        ) as JwtTokenPayload;
    } catch {
        return {
            success: false,
            message: "Invalid or expired refresh token",
            user: null,
        };
    }

    const user = await getUserDetailsById(decodedRefreshToken.userId);
    if (!user) {
        return {
            success: false,
            message: "User not found",
            user: null,
        };
    }

    const session = await getSessionById(decodedRefreshToken.sessionId, decodedRefreshToken.userId);

    if (!session || new Date(session.expires_at) < new Date() || session.revoked_at) {
        return {
            success: false,
            message: "Session is inactive or revoked",
            user: null,
        };
    }

    if (!isCsrfTokenValid(csrfHeader, csrfCookie, session.csrf_secret, token)) {
        return {
            success: false,
            message: "Invalid CSRF verification token",
            user: null,
        };
    }

    return {
        success: true,
        message: "Valid tokens",
        user,
        session,
    };
};
