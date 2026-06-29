const User = require("../models/User");
const LoginAttempt = require("../models/LoginAttempt");
const {
    generateOTP,
    hashOTP,
    verifyOTP,
    isOTPExpired,
    getOTPExpiry,
} = require("../utils/otpHelper");
const { sendOTPEmail } = require("../utils/mailer");
const { createAlert } = require("../utils/alertHelper");
const generateToken = require("../utils/generateToken");
const { updateKnownContext } = require("./contextService");
const { updateTrustScoreOnLogin } = require("./trustScoreService"); // Phase 9

// ─────────────────────────────────────────
// SEND OTP TO USER
// Generates, hashes, stores, and emails OTP
// ─────────────────────────────────────────
const sendMFAOTP = async ({ userId, email, name, loginAttemptId }) => {
    // Hoist so devOTP is available even if the try block throws
    const rawOTP   = generateOTP();
    const expiresAt = getOTPExpiry();
    const expirySeconds = parseInt(process.env.OTP_EXPIRY_SECONDS) || 300;

    try {
        const user = await User.findById(userId).select("+otp +otpExpiresAt");
        if (!user) return { success: false, message: "User not found." };

        // Hash and store OTP
        const hashedOTP = await hashOTP(rawOTP);
        user.otp = hashedOTP;
        user.otpExpiresAt = expiresAt;
        await user.save();

        // Send email (failure here is non-fatal — devOTP still returned in dev)
        const emailResult = await sendOTPEmail({
            to: email,
            name: name || user.name,
            otp: rawOTP,
            expirySeconds,
        });

        if (!emailResult.success) {
            console.warn(`⚠️  OTP email failed for ${email}: ${emailResult.error}`);
        }

        // Mark login attempt as MFA triggered
        if (loginAttemptId) {
            await LoginAttempt.findByIdAndUpdate(loginAttemptId, {
                mfaTriggered: true,
            });
        }

        console.log(`🔐 OTP generated for ${email} — Expires at ${expiresAt.toISOString()}`);

        return {
            success:   true,
            message:   `OTP sent to ${email}. Valid for ${Math.ceil(expirySeconds / 60)} minute(s).`,
            expiresAt,
            emailSent: emailResult.success,
            // Always expose in dev — NEVER in production
            ...(process.env.NODE_ENV === "development" && { devOTP: rawOTP }),
        };

    } catch (error) {
        console.error("❌ MFA OTP send error:", error.message);
        return {
            success: false,
            message: error.message,
            // Still expose OTP in dev so the login flow isn't blocked
            ...(process.env.NODE_ENV === "development" && { devOTP: rawOTP }),
        };
    }
};

// ─────────────────────────────────────────
// VERIFY OTP SUBMITTED BY USER
// ─────────────────────────────────────────
const verifyMFAOTP = async ({ userId, inputOTP, loginAttemptId }) => {
    try {
        const user = await User.findById(userId).select("+otp +otpExpiresAt");
        if (!user) return { success: false, message: "User not found." };

        // Check OTP exists
        if (!user.otp) {
            return {
                success: false,
                message: "No OTP found. Please request a new one.",
                code: "OTP_NOT_FOUND",
            };
        }

        // Check expiry
        if (isOTPExpired(user.otpExpiresAt)) {
            // Clear expired OTP
            user.otp = null;
            user.otpExpiresAt = null;
            await user.save();

            await createAlert({
                alertType: "otp_expired",
                severity: "low",
                userId: user._id,
                email: user.email,
                title: "OTP Expired",
                message: `OTP for account ${user.email} expired before use.`,
            });

            return {
                success: false,
                message: "OTP has expired. Please request a new one.",
                code: "OTP_EXPIRED",
            };
        }

        // Verify OTP
        const isValid = await verifyOTP(inputOTP.toString(), user.otp);

        if (!isValid) {
            await createAlert({
                alertType: "otp_failed",
                severity: "medium",
                userId: user._id,
                email: user.email,
                title: "OTP Verification Failed",
                message: `Incorrect OTP submitted for account ${user.email}.`,
            });

            // ── Phase 9: OTP failure — apply mfa_failed trust penalty ────────
            await updateTrustScoreOnLogin(user._id, {
                success:        false,
                riskScore:      null,
                riskLevel:      "medium",
                mfaTriggered:   true,
                mfaVerified:    false,
                failureReason:  "mfa_failed",
                loginAttemptId: loginAttemptId || null,
            });

            return {
                success: false,
                message: "Invalid OTP. Please try again.",
                code: "OTP_INVALID",
            };
        }

        // ✅ OTP VALID — clear it from DB
        user.otp = null;
        user.otpExpiresAt = null;
        await user.save();

        // Mark login attempt as MFA verified
        let attempt = null;
        if (loginAttemptId) {
            attempt = await LoginAttempt.findByIdAndUpdate(
                loginAttemptId,
                { mfaVerified: true },
                { new: true },
            );

            // Now it's safe to register this context as trusted
            if (attempt?.context?.ipAddress) {
                await updateKnownContext(user._id, {
                    ipAddress:         attempt.context.ipAddress,
                    country:           attempt.context.country,
                    deviceFingerprint: attempt.context.deviceFingerprint,
                    device:            attempt.context.device,
                    browser:           attempt.context.browser,
                    os:                attempt.context.os,
                });
            }
        }

        // ── Phase 9: MFA passed — apply mfa_success trust gain ─────────
        // Only fires for medium-risk logins (high-risk already penalised in authController).
        // We always apply the gain here — the high-risk penalty already happened, so
        // applying a small gain on top is still a net negative, which is correct.
        await updateTrustScoreOnLogin(user._id, {
            success:        true,
            riskScore:      attempt?.riskScore ?? null,
            riskLevel:      attempt?.riskLevel ?? "medium",
            mfaTriggered:   true,
            mfaVerified:    true,
            failureReason:  null,
            loginAttemptId: loginAttemptId || null,
        });

        // Generate final JWT after MFA passes
        const token = generateToken(user._id, user.role);

        return {
            success: true,
            message: "MFA verified successfully. Login complete.",
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                trustScore: user.trustScore,
                riskScore: user.riskScore,
            },
        };

    } catch (error) {
        console.error("❌ MFA verify error:", error.message);
        return { success: false, message: error.message };
    }
};

// ─────────────────────────────────────────
// RESEND OTP
// Rate-limited — not more than once per minute
// ─────────────────────────────────────────
const resendMFAOTP = async ({ userId, email, name }) => {
    try {
        const user = await User.findById(userId).select("+otp +otpExpiresAt");
        if (!user) return { success: false, message: "User not found." };

        // Rate limit — check if last OTP was sent less than 60s ago
        if (user.otpExpiresAt) {
            const expirySeconds = parseInt(process.env.OTP_EXPIRY_SECONDS) || 300;
            const otpAge = expirySeconds - Math.ceil((user.otpExpiresAt - Date.now()) / 1000);

            if (otpAge < 60) {
                return {
                    success: false,
                    message: `Please wait ${60 - otpAge} second(s) before requesting a new OTP.`,
                    code: "RESEND_TOO_SOON",
                    waitSeconds: 60 - otpAge,
                };
            }
        }

        return await sendMFAOTP({ userId, email, name });

    } catch (error) {
        console.error("❌ Resend OTP error:", error.message);
        return { success: false, message: error.message };
    }
};

module.exports = {
    sendMFAOTP,
    verifyMFAOTP,
    resendMFAOTP,
};