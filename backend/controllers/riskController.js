const mongoose   = require("mongoose");
const User = require("../models/User");
const LoginAttempt = require("../models/LoginAttempt");
const {
    evaluateLoginRisk,
    classifyRisk,
    RISK_WEIGHTS,
} = require("../services/riskService");
const { collectContext, compareContext } = require("../services/contextService");
const { calculateBiometricAverages } = require("../services/biometricService");

// ─────────────────────────────────────────
// GET MY CURRENT RISK SCORE
// GET /api/risk/me
// Protected
// ─────────────────────────────────────────
const getMyRiskScore = async (req, res) => {
    try {
        const user = await User.findById(req.user.id);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        // Collect current context
        const context = collectContext(req);
        const contextFlags = compareContext(context, user);

        // Evaluate risk with current context (no fresh biometrics here)
        const riskResult = evaluateLoginRisk({
            user,
            contextFlags,
            currentBiometrics: null,
        });

        return res.status(200).json({
            success: true,
            data: {
                userId: user._id,
                email: user.email,
                riskScore: riskResult.score,
                riskLevel: riskResult.level,
                action: riskResult.action,
                description: riskResult.description,
                factors: riskResult.factors,
                breakdown: riskResult.breakdown,
                trustScore: user.trustScore,
                meta: riskResult.meta,
                context: {
                    ip: context.ipAddress,
                    country: context.country,
                    browser: context.browser,
                    os: context.os,
                    isKnownIP: contextFlags.isKnownIP,
                    isKnownDevice: contextFlags.isKnownDevice,
                    isKnownCountry: contextFlags.isKnownCountry,
                },
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error calculating risk score.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET MY RISK HISTORY (from login attempts)
// GET /api/risk/history
// Protected
// ─────────────────────────────────────────
const getMyRiskHistory = async (req, res) => {
    try {
        const userId = req.user.id;
        const limit = parseInt(req.query.limit) || 20;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        const attempts = await LoginAttempt.find({ userId })
            .sort({ attemptedAt: -1 })
            .skip(skip)
            .limit(limit)
            .select(
                "success riskScore riskLevel riskFactors context.ipAddress context.country context.browser context.isKnownIP context.isKnownDevice mfaTriggered attemptedAt"
            );

        const total = await LoginAttempt.countDocuments({ userId });

        // Risk level breakdown counts
        const breakdown = await LoginAttempt.aggregate([
            { $match: { userId: new mongoose.Types.ObjectId(userId) } },
            {
                $group: {
                    _id: "$riskLevel",
                    count: { $sum: 1 },
                },
            },
        ]);

        // Average risk score
        const avgResult = await LoginAttempt.aggregate([
            {
                $match: {
                    userId: new mongoose.Types.ObjectId(userId),
                    riskScore: { $ne: null },
                },
            },
            {
                $group: {
                    _id: null,
                    avgRiskScore: { $avg: "$riskScore" },
                },
            },
        ]);

        const avgRiskScore = avgResult.length > 0
            ? parseFloat(avgResult[0].avgRiskScore.toFixed(2))
            : 0;

        return res.status(200).json({
            success: true,
            data: {
                attempts,
                stats: {
                    avgRiskScore,
                    breakdown: breakdown.reduce((acc, item) => {
                        if (item._id) acc[item._id] = item.count;
                        return acc;
                    }, {}),
                },
                pagination: {
                    total,
                    page,
                    pages: Math.ceil(total / limit),
                    limit,
                },
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching risk history.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET RISK ENGINE CONFIG (weights + levels)
// GET /api/risk/config
// Admin only
// ─────────────────────────────────────────
const getRiskConfig = async (req, res) => {
    try {
        return res.status(200).json({
            success: true,
            data: {
                weights: RISK_WEIGHTS,
                levels: {
                    low: { range: "0–39", action: "allow" },
                    medium: { range: "40–69", action: "trigger_mfa" },
                    high: { range: "70–100", action: "block_or_mfa" },
                },
                thresholds: {
                    RISK_HIGH_THRESHOLD: process.env.RISK_HIGH_THRESHOLD || 70,
                    RISK_MEDIUM_THRESHOLD: process.env.RISK_MEDIUM_THRESHOLD || 40,
                },
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching risk config.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET RISK SUMMARY FOR ALL USERS
// GET /api/risk/admin/summary
// Admin only
// ─────────────────────────────────────────
const getSystemRiskSummary = async (req, res) => {
    try {
        // Count users by risk level
        const usersByRisk = await User.aggregate([
            {
                $group: {
                    _id: {
                        $switch: {
                            branches: [
                                { case: { $lte: ["$riskScore", 39] }, then: "low" },
                                { case: { $lte: ["$riskScore", 69] }, then: "medium" },
                                { case: { $lte: ["$riskScore", 100] }, then: "high" },
                            ],
                            default: "unknown",
                        },
                    },
                    count: { $sum: 1 },
                    avgRiskScore: { $avg: "$riskScore" },
                },
            },
        ]);

        // Recent high-risk login attempts
        const highRiskAttempts = await LoginAttempt.find({ riskLevel: "high" })
            .sort({ attemptedAt: -1 })
            .limit(10)
            .populate("userId", "name email")
            .select(
                "userId email riskScore riskLevel riskFactors context.ipAddress context.country attemptedAt"
            );

        // Total system stats
        const totalAttempts = await LoginAttempt.countDocuments();
        const totalSuccesses = await LoginAttempt.countDocuments({ success: true });
        const totalFailures = await LoginAttempt.countDocuments({ success: false });
        const totalUsers = await User.countDocuments();
        const lockedUsers = await User.countDocuments({ isLocked: true });

        // Average system risk score
        const avgSystem = await LoginAttempt.aggregate([
            { $match: { riskScore: { $ne: null } } },
            { $group: { _id: null, avg: { $avg: "$riskScore" } } },
        ]);

        return res.status(200).json({
            success: true,
            data: {
                systemStats: {
                    totalUsers,
                    lockedUsers,
                    totalAttempts,
                    totalSuccesses,
                    totalFailures,
                    successRate: totalAttempts > 0
                        ? parseFloat(((totalSuccesses / totalAttempts) * 100).toFixed(2))
                        : 0,
                    avgSystemRiskScore: avgSystem.length > 0
                        ? parseFloat(avgSystem[0].avg.toFixed(2))
                        : 0,
                },
                usersByRiskLevel: usersByRisk.reduce((acc, item) => {
                    if (item._id) acc[item._id] = {
                        count: item.count,
                        avgRiskScore: parseFloat(item.avgRiskScore.toFixed(2)),
                    };
                    return acc;
                }, {}),
                recentHighRiskAttempts: highRiskAttempts,
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching system risk summary.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET RISK DETAILS FOR A USER
// GET /api/risk/admin/:userId
// Admin only
// ─────────────────────────────────────────
const getUserRiskDetails = async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const recentAttempts = await LoginAttempt.find({ userId })
            .sort({ attemptedAt: -1 })
            .limit(20)
            .select(
                "success riskScore riskLevel riskFactors context mfaTriggered mfaVerified attemptedAt"
            );

        // Trend — last 7 days risk scores
        const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
        const riskTrend = await LoginAttempt.find({
            userId,
            attemptedAt: { $gte: sevenDaysAgo },
            riskScore: { $ne: null },
        })
            .sort({ attemptedAt: 1 })
            .select("riskScore riskLevel attemptedAt");

        return res.status(200).json({
            success: true,
            data: {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    currentRiskScore: user.riskScore,
                    currentTrustScore: user.trustScore,
                    isLocked: user.isLocked,
                    failedLoginAttempts: user.failedLoginAttempts,
                    behavioralBaseline: user.behavioralBaseline,
                    knownIPs: user.knownIPs,
                    knownDevices: user.knownDevices,
                    knownCountries: user.knownCountries,
                },
                recentAttempts,
                riskTrend,
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching user risk details.",
            error: error.message,
        });
    }
};

module.exports = {
    getMyRiskScore,
    getMyRiskHistory,
    getRiskConfig,
    getSystemRiskSummary,
    getUserRiskDetails,
};