import { z } from "zod";
import AppError from "../utils/error.ts";

const emailSchema = z.string().email("Invalid email address").toLowerCase().trim();

export const signupKeyGenerator = (email: string): string => {
    const result = emailSchema.safeParse(email);
    if (!result.success) {
        throw new AppError(result.error.issues[0].message, 400);
    }
    return `auth:signup:${result.data}`;
};

export const passwordResetKeyGenerator = (email: string): string => {
    const result = emailSchema.safeParse(email);
    if (!result.success) {
        throw new AppError(result.error.issues[0].message, 400);
    }
    return `auth:password-reset:${result.data}`;
};

export const otpCooldownKeyGenerator = (email: string): string => {
    const result = emailSchema.safeParse(email);
    if (!result.success) {
        throw new AppError(result.error.issues[0].message, 400);
    }
    return `auth:otp-cooldown:${result.data}`;
};
