import { Router } from "express";
import {
    newUserSignUp,
    validateEmailOtp,
    resendSignupOtp,
    loginUser,
    refreshTokens,
    getCurrentUser,
    logoutUser,
    logoutAllUsers,
    getUserSessions,
    revokeUserSession,
    forgotPassword,
    resetPassword,
    changePassword,
    updateUserProfile,
    deleteUserAccount,
} from "../controllers/auth.controller.ts";
import { authentication } from "../middlewares/auth.middleware.ts";
import {
    validateSignup,
    validateVerifyOtp,
    validateResendOtp,
    validateLogin,
    validateForgotPassword,
    validateResetPassword,
    validateChangePassword,
    validateUpdateProfile,
} from "../middlewares/validateBody.ts";

const authRouter = Router();

authRouter.post("/signup", validateSignup, newUserSignUp);
authRouter.post("/verify-otp", validateVerifyOtp, validateEmailOtp);
authRouter.post("/resend-otp", validateResendOtp, resendSignupOtp);
authRouter.post("/login", validateLogin, loginUser);
authRouter.post("/refresh", refreshTokens);
authRouter.post("/forgot-password", validateForgotPassword, forgotPassword);
authRouter.post("/reset-password", validateResetPassword, resetPassword);

authRouter.get("/me", authentication, getCurrentUser);
authRouter.patch("/me", authentication, validateUpdateProfile, updateUserProfile);
authRouter.delete("/me", authentication, deleteUserAccount);

authRouter.post("/logout", authentication, logoutUser);
authRouter.post("/logout-all", authentication, logoutAllUsers);
authRouter.get("/sessions", authentication, getUserSessions);
authRouter.delete("/sessions/:sessionId", authentication, revokeUserSession);
authRouter.patch("/change-password", authentication, validateChangePassword, changePassword);

export default authRouter;
