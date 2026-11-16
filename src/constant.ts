import { CookieOptions } from "express";

export const DB_NAME = "Auth_System";

const isProduction = process.env.NODE_ENV === "production";

export const refreshTokenOption: CookieOptions = {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days in milliseconds
};

export const csrfTokenOptions: CookieOptions = {
    httpOnly: false, // Accessible by JavaScript so client can read and pass it back in header
    secure: isProduction,
    sameSite: "lax",
    maxAge: 7 * 24 * 60 * 60 * 1000,
};
