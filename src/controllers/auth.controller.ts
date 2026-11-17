import asyncHandler from "../utils/asyncHandler.ts";
import AppError from "../utils/error.ts";
import {
    SignupRequestBody,
    VerifyOtpRequestBody,
    ResendOtpRequestBody,
    LoginRequestBody,
    ForgotPasswordRequestBody,
    ResetPasswordRequestBody,
    ChangePasswordRequestBody,
    UpdateProfileRequestBody,
} from "../schema/auth.schema.ts";
import { User, UserWithPassword, SignupDraft } from "../models/User.model.ts";
import { Session } from "../models/Session.model.ts";
import {
    getUserByEmail,
    getUserByEmailWithPassword,
    getUserDetailsById,
    updatePassword,
    updateProfile,
    deleteUser,
    createUserWithClient,
    updateUserLoginWithClient,
} from "../repository/User.repository.ts";
import {
    createSessionWithClient,
    revokeSessionById,
    revokeAllSessions,
    getSessionsByUserId,
    updateSessionById,
} from "../repository/Session.repository.ts";
import {
    signupKeyGenerator,
    passwordResetKeyGenerator,
    otpCooldownKeyGenerator,
} from "../redis/redisKeyGenerator.ts";
import { setRedis, getRedis, deleteRedis } from "../redis/redisHash.ts";
import { hashPassword, verifyPassword } from "../utils/password.ts";
import { sendOtpEmail, sendPasswordResetOtpEmail } from "../utils/emailSender.ts";
import { generateAccessToken, generateRefreshToken, generateCsrfToken } from "../utils/token.ts";
import { csrfTokenOptions, refreshTokenOption } from "../constant.ts";
import { withTransaction } from "../db/db.ts";
import {
    getSessionIdFromRequest,
    getAuthenticatedUser,
    clearAuthenticationCookies,
} from "../services/auth.service.ts";
import { tokenVerification } from "../middlewares/auth.middleware.ts";
import crypto from "node:crypto";

/**
 * 1. User Sign Up
 * Initiates registration by saving draft in Redis and dispatching email OTP.
 */
export const newUserSignUp = asyncHandler(async (req, res) => {
    const body: SignupRequestBody = req.body;
    const name = body.name.trim();
    const email = body.email.trim().toLowerCase();
    const password = body.password.trim();

    const existingUser = await getUserByEmail(email);
    if (existingUser && existingUser.is_verified) {
        throw new AppError("An account with this email already exists", 400);
    }

    const cooldownKey = otpCooldownKeyGenerator(email);
    const cooldown = await getRedis(cooldownKey);
    if (cooldown) {
        throw new AppError("Please wait a minute before requesting another verification code", 429);
    }

    const hashedPassword = await hashPassword(password);
    const emailOtp = String(Math.floor(Math.random() * (999999 - 100000 + 1)) + 100000);

    const draftData: SignupDraft = {
        name,
        email,
        password: hashedPassword,
        otp: emailOtp,
        createdAt: new Date().toISOString(),
    };

    const expiresInMinutes = 5;
    const redisKey = signupKeyGenerator(email);

    await setRedis(redisKey, JSON.stringify(draftData), expiresInMinutes * 60);
    await setRedis(cooldownKey, JSON.stringify({ sent: true }), 60); // 60s cooldown
    await sendOtpEmail(email, emailOtp, expiresInMinutes);

    return res.status(201).json({
        success: true,
        message: "Verification OTP was sent to your email successfully",
    });
});

/**
 * 2. Validate Email OTP
 * Verifies OTP from Redis, writes user to PostgreSQL, initializes session and logs in.
 */
export const validateEmailOtp = asyncHandler(async (req, res) => {
    const { email, otp }: VerifyOtpRequestBody = req.body;
    const cleanEmail = email.trim().toLowerCase();

    const redisKey = signupKeyGenerator(cleanEmail);
    const draft = await getRedis<SignupDraft>(redisKey);

    if (!draft) {
        throw new AppError("Verification session expired or not found. Please sign up again.", 400);
    }

    if (String(draft.otp) !== String(otp).trim()) {
        throw new AppError("Invalid verification code", 401);
    }

    const csrfSecret = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    const userAgent = req.get("user-agent") ?? null;
    const ipAddress = req.ip || "127.0.0.1";

    const { user, session } = await withTransaction(async (client) => {
        const newUser = await createUserWithClient(
            client,
            draft.name,
            draft.email,
            draft.password,
            true // is_verified
        );

        const newSession = await createSessionWithClient(
            client,
            newUser.id,
            ipAddress,
            csrfSecret,
            expiresAt,
            userAgent
        );

        const updatedUser = await updateUserLoginWithClient(client, newUser.id);
        return { user: updatedUser, session: newSession };
    });

    await deleteRedis(redisKey);
    await deleteRedis(otpCooldownKeyGenerator(cleanEmail));

    const accessToken = generateAccessToken(user.id, session.id, user.email, user.name);
    const refreshToken = generateRefreshToken(user.id, session.id, user.email, user.name);
    const csrfToken = generateCsrfToken(refreshToken, csrfSecret);

    res.set("Authorization", "Bearer " + accessToken);
    res.cookie("refreshToken", refreshToken, refreshTokenOption);
    res.cookie("csrfToken", csrfToken, csrfTokenOptions);

    return res.status(201).json({
        success: true,
        message: "Account verified and registered successfully",
        accessToken,
        user,
    });
});

/**
 * 3. Resend Sign Up OTP
 */
export const resendSignupOtp = asyncHandler(async (req, res) => {
    const { email }: ResendOtpRequestBody = req.body;
    const cleanEmail = email.trim().toLowerCase();

    const redisKey = signupKeyGenerator(cleanEmail);
    const draft = await getRedis<SignupDraft>(redisKey);

    if (!draft) {
        throw new AppError(
            "No pending registration found for this email. Please sign up again.",
            404
        );
    }

    const cooldownKey = otpCooldownKeyGenerator(cleanEmail);
    const cooldown = await getRedis(cooldownKey);
    if (cooldown) {
        throw new AppError("Please wait before requesting another verification code", 429);
    }

    const newOtp = String(Math.floor(Math.random() * (999999 - 100000 + 1)) + 100000);
    draft.otp = newOtp;

    const expiresInMinutes = 5;
    await setRedis(redisKey, JSON.stringify(draft), expiresInMinutes * 60);
    await setRedis(cooldownKey, JSON.stringify({ sent: true }), 60);
    await sendOtpEmail(cleanEmail, newOtp, expiresInMinutes);

    return res.status(200).json({
        success: true,
        message: "A fresh verification code has been sent to your email",
    });
});

/**
 * 4. Login User
 * Authenticates email + password and creates a new tracked session.
 */
export const loginUser = asyncHandler(async (req, res) => {
    const { email, password }: LoginRequestBody = req.body;
    const cleanEmail = email.trim().toLowerCase();

    const userData: UserWithPassword | null = await getUserByEmailWithPassword(cleanEmail);
    if (!userData) {
        throw new AppError("Invalid email or password", 401);
    }

    const isPasswordValid = await verifyPassword(password, userData.password);
    if (!isPasswordValid) {
        throw new AppError("Invalid email or password", 401);
    }

    if (!userData.is_verified) {
        throw new AppError("Please verify your email before logging in", 403);
    }

    const csrfSecret = crypto.randomBytes(32).toString("hex");
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    const userAgent = req.get("user-agent") ?? null;
    const ipAddress = req.ip || "127.0.0.1";

    const { session, user } = await withTransaction(async (client) => {
        const session = (await createSessionWithClient(
            client,
            userData.id,
            ipAddress,
            csrfSecret,
            expiresAt,
            userAgent
        )) as Session;

        const user = await updateUserLoginWithClient(client, userData.id);
        return { session, user };
    });

    const accessToken = generateAccessToken(user.id, session.id, user.email, user.name);
    const refreshToken = generateRefreshToken(user.id, session.id, user.email, user.name);
    const csrfToken = generateCsrfToken(refreshToken, csrfSecret);

    res.set("Authorization", "Bearer " + accessToken);
    res.cookie("refreshToken", refreshToken, refreshTokenOption);
    res.cookie("csrfToken", csrfToken, csrfTokenOptions);

    return res.status(200).json({
        success: true,
        message: "Login successful",
        accessToken,
        user,
    });
});

/**
 * 5. Refresh Tokens
 * Explicit endpoint for clients requesting access token renewal using refresh & CSRF tokens.
 */
export const refreshTokens = asyncHandler(async (req, res) => {
    const csrfHeader = (req.headers["x-csrf-token"] as string) || "";
    const csrfCookie = req.cookies?.csrfToken || "";
    const refreshToken = req.cookies?.refreshToken || "";

    const isTokenValid = await tokenVerification(refreshToken, csrfHeader, csrfCookie);
    if (!isTokenValid.success || !isTokenValid.user || !isTokenValid.session) {
        throw new AppError("Session expired or invalid. Please log in again.", 401);
    }

    const newSecretKey = crypto.randomBytes(32).toString("hex");
    const newExpiryDate = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await updateSessionById(
        isTokenValid.session.id,
        isTokenValid.user.id,
        newSecretKey,
        newExpiryDate
    );

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

    return res.status(200).json({
        success: true,
        message: "Tokens renewed successfully",
        accessToken: newAccessToken,
    });
});

/**
 * 6. Get Current User Profile
 */
export const getCurrentUser = asyncHandler(async (req, res) => {
    const user = getAuthenticatedUser(req);
    const userDetails = await getUserDetailsById(user.id);

    if (!userDetails) throw new AppError("User account not found", 404);

    return res.status(200).json({
        success: true,
        user: userDetails,
    });
});

/**
 * 7. Logout User
 * Revokes current session and clears authentication cookies.
 */
export const logoutUser = asyncHandler(async (req, res) => {
    const user = getAuthenticatedUser(req);
    const sessionId = getSessionIdFromRequest(req);

    await revokeSessionById(sessionId, user.id, "logout");
    clearAuthenticationCookies(res);

    return res.status(200).json({
        success: true,
        message: "Logout successful",
    });
});

/**
 * 8. Logout From All Devices
 * Revokes every active session for this user.
 */
export const logoutAllUsers = asyncHandler(async (req, res) => {
    const user = getAuthenticatedUser(req);
    await revokeAllSessions(user.id, "logout_all");
    clearAuthenticationCookies(res);

    return res.status(200).json({
        success: true,
        message: "Logged out from all active sessions",
    });
});

/**
 * 9. Get User Active Sessions
 */
export const getUserSessions = asyncHandler(async (req, res) => {
    const user = getAuthenticatedUser(req);
    const sessions = await getSessionsByUserId(user.id);

    return res.status(200).json({
        success: true,
        sessions,
    });
});

/**
 * 10. Revoke a Specific Session
 */
export const revokeUserSession = asyncHandler(async (req, res) => {
    const user = getAuthenticatedUser(req);
    const targetSessionId =
        typeof req.params.sessionId === "string" ? req.params.sessionId.trim() : "";

    if (!targetSessionId) throw new AppError("Session ID parameter is required", 400);

    const revokedSession = await revokeSessionById(targetSessionId, user.id, "user_revoked");
    if (!revokedSession) throw new AppError("Session not found or already inactive", 404);

    if (targetSessionId === getSessionIdFromRequest(req)) {
        clearAuthenticationCookies(res);
    }

    return res.status(200).json({
        success: true,
        message: "Session revoked successfully",
    });
});

/**
 * 11. Forgot Password (Request OTP)
 */
export const forgotPassword = asyncHandler(async (req, res) => {
    const { email }: ForgotPasswordRequestBody = req.body;
    const cleanEmail = email.trim().toLowerCase();

    const user = await getUserByEmail(cleanEmail);

    if (user && user.is_verified) {
        const otp = String(Math.floor(Math.random() * (999999 - 100000 + 1)) + 100000);
        const expiresInMinutes = 5;
        const resetKey = passwordResetKeyGenerator(cleanEmail);

        await setRedis(resetKey, JSON.stringify({ email: cleanEmail, otp }), expiresInMinutes * 60);
        await sendPasswordResetOtpEmail(cleanEmail, otp, expiresInMinutes);
    }

    return res.status(200).json({
        success: true,
        message: "If an account exists with this email, a password reset code was sent.",
    });
});

/**
 * 12. Reset Password
 * Verifies reset OTP, updates password, and revokes all active sessions for security.
 */
export const resetPassword = asyncHandler(async (req, res) => {
    const { email, otp, newPassword }: ResetPasswordRequestBody = req.body;
    const cleanEmail = email.trim().toLowerCase();

    const resetKey = passwordResetKeyGenerator(cleanEmail);
    const resetData = await getRedis<{ email: string; otp: string }>(resetKey);

    if (!resetData || String(resetData.otp) !== String(otp).trim()) {
        throw new AppError("Invalid or expired password reset verification code", 400);
    }

    const user = await getUserByEmail(cleanEmail);
    if (!user) throw new AppError("User not found", 404);

    await updatePassword(user.id, newPassword);
    await revokeAllSessions(user.id, "password_reset");
    await deleteRedis(resetKey);

    return res.status(200).json({
        success: true,
        message: "Password reset successfully. Please log in with your new password.",
    });
});

/**
 * 13. Change Password (Authenticated)
 */
export const changePassword = asyncHandler(async (req, res) => {
    const user = getAuthenticatedUser(req);
    const { oldPassword, newPassword }: ChangePasswordRequestBody = req.body;

    const userCreds = await getUserByEmailWithPassword(user.email);
    if (!userCreds) throw new AppError("User account not found", 404);

    const isMatch = await verifyPassword(oldPassword, userCreds.password);
    if (!isMatch) throw new AppError("Incorrect current password", 401);

    await updatePassword(user.id, newPassword);

    // Revoke all other sessions for security, keep current
    const currentSessionId = getSessionIdFromRequest(req);
    const allSessions = await getSessionsByUserId(user.id);
    for (const s of allSessions) {
        if (s.id !== currentSessionId && !s.revoked_at) {
            await revokeSessionById(s.id, user.id, "password_changed");
        }
    }

    return res.status(200).json({
        success: true,
        message: "Password changed successfully",
    });
});

/**
 * 14. Update Profile
 */
export const updateUserProfile = asyncHandler(async (req, res) => {
    const user = getAuthenticatedUser(req);
    const { name }: UpdateProfileRequestBody = req.body;

    const updated = await updateProfile(user.id, name.trim());
    return res.status(200).json({
        success: true,
        message: "Profile updated successfully",
        user: updated,
    });
});

/**
 * 15. Delete Account
 */
export const deleteUserAccount = asyncHandler(async (req, res) => {
    const user = getAuthenticatedUser(req);
    const deleted = await deleteUser(user.id);

    if (!deleted) throw new AppError("User not found", 404);

    clearAuthenticationCookies(res);

    return res.status(200).json({
        success: true,
        message: "Account deleted successfully",
    });
});
