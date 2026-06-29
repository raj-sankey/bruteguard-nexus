const {
    getRiskTrend,
    getLoginStats,
    getAttackStats,
    getTrustScoreTrend,
} = require("../services/analyticsService");

// ─────────────────────────────────────────
// GET MY RISK TREND
// GET /api/analytics/me/risk-trend?days=30
// Protected — scoped to the authenticated user
// ─────────────────────────────────────────
const getMyRiskTrend = async (req, res) => {
    try {
        const { days } = req.query;

        const result = await getRiskTrend({
            userId: req.user.id,
            days:   parseInt(days) || 30,
        });

        return res.status(200).json({
            success: true,
            ...result,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching risk trend.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET MY TRUST SCORE TREND
// GET /api/analytics/me/trust-trend?days=30
// Protected — scoped to the authenticated user
// ─────────────────────────────────────────
const getMyTrustTrend = async (req, res) => {
    try {
        const { days } = req.query;

        const result = await getTrustScoreTrend({
            userId: req.user.id,
            days:   parseInt(days) || 30,
        });

        return res.status(200).json({
            success: true,
            ...result,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching trust score trend.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET SYSTEM RISK TREND
// GET /api/analytics/admin/risk-trend?days=30
// Protected + adminOnly
// ─────────────────────────────────────────
const getSystemRiskTrend = async (req, res) => {
    try {
        const { days } = req.query;

        const result = await getRiskTrend({
            userId: null,           // null → system-wide
            days:   parseInt(days) || 30,
        });

        return res.status(200).json({
            success: true,
            ...result,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching system risk trend.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET LOGIN STATS
// GET /api/analytics/admin/login-stats?period=daily|weekly|monthly&days=30
// Protected + adminOnly
// ─────────────────────────────────────────
const getLoginStatsAdmin = async (req, res) => {
    try {
        const { period, days } = req.query;

        // Validate period param
        const safePeriod = ["daily", "weekly", "monthly"].includes(period) ? period : "daily";

        const result = await getLoginStats({
            userId: null,          // system-wide
            period: safePeriod,
            days:   parseInt(days) || 30,
        });

        return res.status(200).json({
            success: true,
            ...result,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching login statistics.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET ATTACK STATS
// GET /api/analytics/admin/attack-stats?days=30
// Protected + adminOnly
// ─────────────────────────────────────────
const getAttackStatsAdmin = async (req, res) => {
    try {
        const { days } = req.query;

        const result = await getAttackStats({
            days: parseInt(days) || 30,
        });

        return res.status(200).json({
            success: true,
            ...result,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching attack statistics.",
            error: error.message,
        });
    }
};

module.exports = {
    getMyRiskTrend,
    getMyTrustTrend,
    getSystemRiskTrend,
    getLoginStatsAdmin,
    getAttackStatsAdmin,
};
