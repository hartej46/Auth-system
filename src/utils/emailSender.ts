import nodemailer from "nodemailer";
import AppError from "./error.ts";

const smtpHost = process.env.SMTP_HOST ?? "smtp.gmail.com";
const smtpPort = Number(process.env.SMTP_PORT ?? 587);
const smtpUser = process.env.SMTP_USER;
const smtpPassword = process.env.SMTP_PASS;
const appName = process.env.APP_NAME ?? "Auth System";

const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: false,
    requireTLS: true,
    auth: {
        user: smtpUser ?? "",
        pass: smtpPassword ?? "",
    },
});

const sendEmail = async (
    recipientEmail: string,
    subject: string,
    text: string,
    html: string
): Promise<void> => {
    if (!smtpUser || !smtpPassword) {
        console.warn(
            "SMTP credentials not fully configured. Email was not sent to:",
            recipientEmail
        );
        return;
    }

    try {
        const delivery = await transporter.sendMail({
            from: `${appName} Security Team <${smtpUser}>`,
            to: recipientEmail,
            subject,
            text,
            html,
        });

        console.info("Email delivered successfully", {
            messageId: delivery.messageId,
            accepted: delivery.accepted,
        });
    } catch (error: unknown) {
        if (error && typeof error === "object" && "code" in error) {
            const code = (error as { code?: string }).code;
            if (code === "EAUTH") {
                throw new AppError(
                    "Failed to authenticate with SMTP server. Verify your credentials/app password.",
                    500
                );
            }
        }

        const errorMessage = error instanceof Error ? error.message : "SMTP email delivery failed";
        throw new AppError(errorMessage, 500);
    }
};

const createOtpHtml = (otp: number | string, expiresInMinutes: number, title: string): string => `
    <div style="margin: 0; padding: 32px 16px; background-color: #f1f5f9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1e293b;">
        <table role="presentation" cellpadding="0" cellspacing="0" width="100%" style="max-width: 540px; margin: 0 auto; background-color: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);">
            <tr>
                <td style="padding: 28px 32px; background-color: #0284c7; text-align: center;">
                    <h1 style="margin: 0; color: #ffffff; font-size: 24px; font-weight: 700;">${appName}</h1>
                    <p style="margin: 6px 0 0; color: #e0f2fe; font-size: 14px;">${title}</p>
                </td>
            </tr>
            <tr>
                <td style="padding: 36px 32px; text-align: center;">
                    <h2 style="margin: 0 0 12px; color: #0f172a; font-size: 20px;">${title}</h2>
                    <p style="margin: 0; color: #64748b; font-size: 15px; line-height: 1.6;">Use the 6-digit verification code below to proceed.</p>
                    <div style="display: inline-block; margin: 24px 0; padding: 14px 28px; background-color: #f0f9ff; border: 2px dashed #0284c7; border-radius: 10px;">
                        <span style="color: #0369a1; font-size: 32px; font-weight: bold; letter-spacing: 8px;">${otp}</span>
                    </div>
                    <p style="margin: 0; color: #ea580c; font-size: 14px; font-weight: 600;">This code will expire in ${expiresInMinutes} minutes.</p>
                    <p style="margin: 20px 0 0; color: #94a3b8; font-size: 13px; line-height: 1.5;">If you did not request this verification code, please ignore this email or secure your account.</p>
                </td>
            </tr>
            <tr>
                <td style="padding: 16px 32px; background-color: #f8fafc; text-align: center; border-top: 1px solid #f1f5f9;">
                    <p style="margin: 0; color: #94a3b8; font-size: 12px;">This is an automated system email. Please do not reply.</p>
                </td>
            </tr>
        </table>
    </div>`;

export const sendOtpEmail = async (
    recipientEmail: string,
    otp: number | string,
    expiresInMinutes: number
): Promise<void> => {
    await sendEmail(
        recipientEmail,
        `Verify your ${appName} Account`,
        `Your verification code is ${otp}. It expires in ${expiresInMinutes} minutes.`,
        createOtpHtml(otp, expiresInMinutes, "Account Verification")
    );
};

export const sendPasswordResetOtpEmail = async (
    recipientEmail: string,
    otp: number | string,
    expiresInMinutes: number
): Promise<void> => {
    await sendEmail(
        recipientEmail,
        `Reset your ${appName} Password`,
        `Your password reset code is ${otp}. It expires in ${expiresInMinutes} minutes.`,
        createOtpHtml(otp, expiresInMinutes, "Password Reset Request")
    );
};

export default sendOtpEmail;
