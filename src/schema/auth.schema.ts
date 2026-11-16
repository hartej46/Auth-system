import { z } from "zod";

export const SignupSchema = z.object({
    name: z.string().trim().min(2, "Name must be at least 2 characters"),
    email: z.string().trim().email("Invalid email address").toLowerCase(),
    password: z.string().min(8, "Password must be at least 8 characters long"),
});

export const VerifyOtpSchema = z.object({
    email: z.string().trim().email("Invalid email address").toLowerCase(),
    otp: z
        .string()
        .trim()
        .regex(/^\d{6}$/, "OTP must be exactly 6 digits"),
});

export const ResendOtpSchema = z.object({
    email: z.string().trim().email("Invalid email address").toLowerCase(),
});

export const LoginSchema = z.object({
    email: z.string().trim().email("Invalid email address").toLowerCase(),
    password: z.string().min(8, "Password must be at least 8 characters long"),
});

export const ForgotPasswordSchema = z.object({
    email: z.string().trim().email("Invalid email address").toLowerCase(),
});

export const ResetPasswordSchema = z.object({
    email: z.string().trim().email("Invalid email address").toLowerCase(),
    otp: z
        .string()
        .trim()
        .regex(/^\d{6}$/, "OTP must be exactly 6 digits"),
    newPassword: z.string().min(8, "New password must be at least 8 characters long"),
});

export const ChangePasswordSchema = z.object({
    oldPassword: z.string().min(1, "Old password is required"),
    newPassword: z.string().min(8, "New password must be at least 8 characters long"),
});

export const UpdateProfileSchema = z.object({
    name: z.string().trim().min(2, "Name must be at least 2 characters"),
});

export type SignupRequestBody = z.infer<typeof SignupSchema>;
export type VerifyOtpRequestBody = z.infer<typeof VerifyOtpSchema>;
export type ResendOtpRequestBody = z.infer<typeof ResendOtpSchema>;
export type LoginRequestBody = z.infer<typeof LoginSchema>;
export type ForgotPasswordRequestBody = z.infer<typeof ForgotPasswordSchema>;
export type ResetPasswordRequestBody = z.infer<typeof ResetPasswordSchema>;
export type ChangePasswordRequestBody = z.infer<typeof ChangePasswordSchema>;
export type UpdateProfileRequestBody = z.infer<typeof UpdateProfileSchema>;
