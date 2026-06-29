const User = require("../models/User");
const LoginAttempt = require("../models/LoginAttempt");
const {
    sendMFAOTP,
    verifyMFAOTP,
    resendMFAOTP,
} = require("../services/mfaService");
const { extractIP } = require("../utils/getIPInfo");

// ─────────────────────────────────────────
// REQUEST OTP
// POST /api/mfa/send-otp
// Public — called after login returns mfa_required
// ─────────────────────────────────────────
const requestOTP = async (req, res) => {
    try {
        const { userId, email, loginAttemptId } = req.body;

        if (!userId || !email) {
            return res.status(400).json({
                success: false,
                message: "userId and email are required.",
            });
        }

        // Verify user exists
        const user = await User.findById(userId);
        if (!user || user.email !== email) {
            return res.status(404).json({
                success: false,
                message: "User not found or email mismatch.",
            });
        }

        const result = await sendMFAOTP({
            userId,
            email,
            name: user.name,
            loginAttemptId: loginAttemptId || null,
        });

        if (!result.success) {
            return res.status(500).json({
                success: false,
                message: result.message,
            });
        }

        return res.status(200).json({
            success: true,
            message: result.message,
            expiresAt: result.expiresAt,
            emailSent: result.emailSent,
            // Dev only
            ...(process.env.NODE_ENV === "development" && { devOTP: result.devOTP }),
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error sending OTP.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// VERIFY OTP
// POST /api/mfa/verify-otp
// Public — called from OTP verification page
// ─────────────────────────────────────────
const verifyOTP = async (req, res) => {
    try {
        const { userId, otp, loginAttemptId } = req.body;

        if (!userId || !otp) {
            return res.status(400).json({
                success: false,
                message: "userId and OTP are required.",
            });
        }

        if (otp.toString().length !== 6) {
            return res.status(400).json({
                success: false,
                message: "OTP must be exactly 6 digits.",
            });
        }

        const result = await verifyMFAOTP({
            userId,
            inputOTP: otp.toString(),
            loginAttemptId: loginAttemptId || null,
        });

        if (!result.success) {
            // Map error codes to HTTP status
            const status =
                result.code === "OTP_EXPIRED" ? 410 :
                    result.code === "OTP_NOT_FOUND" ? 404 : 401;

            return res.status(status).json({
                success: false,
                message: result.message,
                code: result.code,
            });
        }

        return res.status(200).json({
            success: true,
            message: result.message,
            token: result.token,
            user: result.user,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error verifying OTP.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// RESEND OTP
// POST /api/mfa/resend-otp
// Public
// ─────────────────────────────────────────
const resendOTP = async (req, res) => {
    try {
        const { userId, email } = req.body;

        if (!userId || !email) {
            return res.status(400).json({
                success: false,
                message: "userId and email are required.",
            });
        }

        const user = await User.findById(userId);
        if (!user || user.email !== email) {
            return res.status(404).json({
                success: false,
                message: "User not found or email mismatch.",
            });
        }

        const result = await resendMFAOTP({
            userId,
            email,
            name: user.name,
        });

        if (!result.success) {
            const status = result.code === "RESEND_TOO_SOON" ? 429 : 500;
            return res.status(status).json({
                success: false,
                message: result.message,
                waitSeconds: result.waitSeconds || null,
            });
        }

        return res.status(200).json({
            success: true,
            message: result.message,
            expiresAt: result.expiresAt,
            // Dev only
            ...(process.env.NODE_ENV === "development" && { devOTP: result.devOTP }),
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error resending OTP.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET MFA STATUS (for current user)
// GET /api/mfa/status
// Protected
// ─────────────────────────────────────────
const getMFAStatus = async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("+otpExpiresAt");

        const hasPendingOTP = user.otpExpiresAt && user.otpExpiresAt > new Date();
        const expirySeconds = parseInt(process.env.OTP_EXPIRY_SECONDS) || 300;

        return res.status(200).json({
            success: true,
            data: {
                userId: user._id,
                email: user.email,
                hasPendingOTP,
                otpExpiresAt: hasPendingOTP ? user.otpExpiresAt : null,
                remainingSeconds: hasPendingOTP
                    ? Math.ceil((user.otpExpiresAt - Date.now()) / 1000)
                    : 0,
                mfaConfig: {
                    otpExpirySeconds: expirySeconds,
                    otpLength: 6,
                    mediumRiskTrigger: parseInt(process.env.RISK_MEDIUM_THRESHOLD) || 40,
                    highRiskTrigger: parseInt(process.env.RISK_HIGH_THRESHOLD) || 70,
                },
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching MFA status.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET MFA STATS
// GET /api/mfa/admin/stats
// Admin only
// ─────────────────────────────────────────
const getMFAStats = async (req, res) => {
    try {
        const totalTriggered = await LoginAttempt.countDocuments({ mfaTriggered: true });
        const totalVerified = await LoginAttempt.countDocuments({ mfaTriggered: true, mfaVerified: true });
        const totalFailed = totalTriggered - totalVerified;

        const last24h = new Date(Date.now() - 24 * 60 * 60 * 1000);
        const last24hTriggered = await LoginAttempt.countDocuments({
            mfaTriggered: true,
            attemptedAt: { $gte: last24h },
        });

        const successRate = totalTriggered > 0
            ? parseFloat(((totalVerified / totalTriggered) * 100).toFixed(2))
            : 0;

        // By risk level
        const mfaByRisk = await LoginAttempt.aggregate([
            { $match: { mfaTriggered: true } },
            {
                $group: {
                    _id: "$riskLevel",
                    count: { $sum: 1 },
                    verified: {
                        $sum: { $cond: ["$mfaVerified", 1, 0] },
                    },
                },
            },
        ]);

        return res.status(200).json({
            success: true,
            data: {
                totalMFATriggered: totalTriggered,
                totalMFAVerified: totalVerified,
                totalMFAFailed: totalFailed,
                last24hTriggered,
                successRate: `${successRate}%`,
                byRiskLevel: mfaByRisk.reduce((acc, item) => {
                    if (item._id) acc[item._id] = { triggered: item.count, verified: item.verified };
                    return acc;
                }, {}),
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching MFA stats.",
            error: error.message,
        });
    }
};

module.exports = {
    requestOTP,
    verifyOTP,
    resendOTP,
    getMFAStatus,
    getMFAStats,
};