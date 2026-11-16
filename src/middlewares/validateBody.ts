import asyncHandler from "../utils/asyncHandler.ts";
import AppError from "../utils/error.ts";
import { ZodSchema } from "zod";
import {
    SignupSchema,
    VerifyOtpSchema,
    ResendOtpSchema,
    LoginSchema,
    ForgotPasswordSchema,
    ResetPasswordSchema,
    ChangePasswordSchema,
    UpdateProfileSchema,
} from "../schema/auth.schema.ts";

/**
 * Generic validator middleware factory for any Zod schema.
 */
export const validateBody = (schema: ZodSchema) =>
    asyncHandler(async (req, _res, next) => {
        const result = schema.safeParse(req.body);
        if (!result.success) {
            throw new AppError(result.error.issues[0].message, 400);
        }
        req.body = result.data;
        return next();
    });

export const validateSignup = validateBody(SignupSchema);
export const validateVerifyOtp = validateBody(VerifyOtpSchema);
export const validateResendOtp = validateBody(ResendOtpSchema);
export const validateLogin = validateBody(LoginSchema);
export const validateForgotPassword = validateBody(ForgotPasswordSchema);
export const validateResetPassword = validateBody(ResetPasswordSchema);
export const validateChangePassword = validateBody(ChangePasswordSchema);
export const validateUpdateProfile = validateBody(UpdateProfileSchema);
