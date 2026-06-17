const User = require("../models/User");
const LoginAttempt = require("../models/LoginAttempt");
const { collectContext } = require("../services/contextService");

// ─────────────────────────────────────────
// GET MY CONTEXT (current request)
// GET /api/context/me
// Protected
// ─────────────────────────────────────────
const getMyContext = async (req, res) => {
    try {
        const context = collectContext(req);
        const user = await User.findById(req.user.id);

        return res.status(200).json({
            success: true,
            message: "Current session context captured.",
            data: {
                current: context,
                knownProfile: {
                    knownIPs: user.knownIPs,
                    knownDevices: user.knownDevices,
                    knownCountries: user.knownCountries,
                },
                flags: {
                    isKnownIP: user.knownIPs.includes(context.ipAddress),
                    isKnownDevice: user.knownDevices.includes(context.deviceFingerprint),
                    isKnownCountry: user.knownCountries.includes(context.country),
                },
            },
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error collecting context.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET MY LOGIN LOCATION HISTORY
// GET /api/context/locations
// Protected
// ─────────────────────────────────────────
const getLocationHistory = async (req, res) => {
    try {
        const userId = req.user.id;
        const limit = parseInt(req.query.limit) || 20;

        const attempts = await LoginAttempt.find({ userId, success: true })
            .sort({ attemptedAt: -1 })
            .limit(limit)
            .select(
                "context.ipAddress context.country context.city context.region context.browser context.os context.device context.isKnownIP context.isKnownDevice attemptedAt"
            );

        // Group unique locations
        const uniqueCountries = [
            ...new Set(attempts.map((a) => a.context?.country).filter(Boolean)),
        ];

        const uniqueIPs = [
            ...new Set(attempts.map((a) => a.context?.ipAddress).filter(Boolean)),
        ];

        return res.status(200).json({
            success: true,
            data: {
                loginHistory: attempts,
                summary: {
                    uniqueCountries,
                    uniqueIPs,
                    totalLogins: attempts.length,
                },
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching location history.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET MY KNOWN DEVICES
// GET /api/context/devices
// Protected
// ─────────────────────────────────────────
const getMyDevices = async (req, res) => {
    try {
        const user = await User.findById(req.user.id);

        // Get last login per device fingerprint
        const deviceAttempts = await LoginAttempt.aggregate([
            { $match: { userId: user._id, success: true } },
            { $sort: { attemptedAt: -1 } },
            {
                $group: {
                    _id: "$context.deviceFingerprint",
                    device: { $first: "$context.device" },
                    browser: { $first: "$context.browser" },
                    os: { $first: "$context.os" },
                    lastSeen: { $first: "$attemptedAt" },
                    loginCount: { $sum: 1 },
                },
            },
            { $sort: { lastSeen: -1 } },
        ]);

        return res.status(200).json({
            success: true,
            data: {
                knownDeviceFingerprints: user.knownDevices,
                deviceDetails: deviceAttempts,
                totalDevices: user.knownDevices.length,
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching devices.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// CLEAR KNOWN CONTEXT (force re-verify all)
// DELETE /api/context/reset
// Protected
// ─────────────────────────────────────────
const resetKnownContext = async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, {
            knownIPs: [],
            knownDevices: [],
            knownCountries: [],
        });

        return res.status(200).json({
            success: true,
            message:
                "Known context cleared. All future logins will be treated as new until verified.",
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error resetting context.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET CONTEXT HISTORY FOR ANY USER
// GET /api/context/admin/:userId
// Admin only
// ─────────────────────────────────────────
const getAdminUserContext = async (req, res) => {
    try {
        const { userId } = req.params;
        const limit = parseInt(req.query.limit) || 30;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const attempts = await LoginAttempt.find({ userId })
            .sort({ attemptedAt: -1 })
            .limit(limit)
            .select("success context riskScore riskLevel attemptedAt");

        return res.status(200).json({
            success: true,
            data: {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    knownIPs: user.knownIPs,
                    knownDevices: user.knownDevices,
                    knownCountries: user.knownCountries,
                },
                loginHistory: attempts,
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching user context.",
            error: error.message,
        });
    }
};

module.exports = {
    getMyContext,
    getLocationHistory,
    getMyDevices,
    resetKnownContext,
    getAdminUserContext,
};