import jwt from "jsonwebtoken";
import AppError from "./error.ts";
import crypto from "node:crypto";

const generateAccessToken = (
    userId: string | number,
    sessionId: string,
    email: string,
    name: string
): string => {
    if (!process.env.ACCESS_TOKEN_GENERATOR || !process.env.ACCESS_TOKEN_EXPIRY) {
        throw new AppError("JWT access token environment variables not configured", 500);
    }

    return jwt.sign(
        {
            userId: String(userId),
            sessionId,
            email,
            name,
        },
        process.env.ACCESS_TOKEN_GENERATOR,
        {
            expiresIn: process.env.ACCESS_TOKEN_EXPIRY as jwt.SignOptions["expiresIn"],
        }
    );
};

const generateRefreshToken = (
    userId: string | number,
    sessionId: string,
    email: string,
    name: string
): string => {
    if (!process.env.REFRESH_TOKEN_GENERATOR || !process.env.REFRESH_TOKEN_EXPIRY) {
        throw new AppError("JWT refresh token environment variables not configured", 500);
    }

    return jwt.sign(
        {
            userId: String(userId),
            sessionId,
            email,
            name,
        },
        process.env.REFRESH_TOKEN_GENERATOR,
        {
            expiresIn: process.env.REFRESH_TOKEN_EXPIRY as jwt.SignOptions["expiresIn"],
        }
    );
};

const verifyAccessToken = (token: string) => {
    return jwt.verify(token, process.env.ACCESS_TOKEN_GENERATOR!);
};

const verifyRefreshToken = (token: string) => {
    return jwt.verify(token, process.env.REFRESH_TOKEN_GENERATOR!);
};

const generateCsrfToken = (token: string, key: string): string => {
    return crypto.createHmac("sha256", key).update(token).digest("hex");
};

const isCsrfTokenValid = (
    csrfHeader: string,
    csrfCookie: string,
    csrf_secret: string,
    token: string
): boolean => {
    if (!csrfHeader || !csrfCookie || !csrf_secret || !token) {
        return false;
    }

    const expectedCsrfToken = crypto.createHmac("sha256", csrf_secret).update(token).digest("hex");

    const expectedCsrfBuffer = Buffer.from(expectedCsrfToken);
    const headerCsrfBuffer = Buffer.from(csrfHeader);
    const cookieCsrfBuffer = Buffer.from(csrfCookie);

    if (
        expectedCsrfBuffer.length !== headerCsrfBuffer.length ||
        expectedCsrfBuffer.length !== cookieCsrfBuffer.length
    ) {
        return false;
    }

    return (
        crypto.timingSafeEqual(expectedCsrfBuffer, headerCsrfBuffer) &&
        crypto.timingSafeEqual(expectedCsrfBuffer, cookieCsrfBuffer)
    );
};

export {
    generateAccessToken,
    generateRefreshToken,
    verifyAccessToken,
    verifyRefreshToken,
    generateCsrfToken,
    isCsrfTokenValid,
};
