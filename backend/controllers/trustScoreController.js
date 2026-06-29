const User = require("../models/User");
const {
    getTrustScoreHistory,
    getTrustLevel,
    getRecentContributingEvents,
} = require("../services/trustScoreService");

// ─────────────────────────────────────────
// GET MY TRUST SCORE
// GET /api/trust/me
// Protected — authenticated user's own score
// ─────────────────────────────────────────
const getMyTrustScore = async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select("trustScore riskScore email name");

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const level = getTrustLevel(user.trustScore);

        // Pull the 10 most recent events for the breakdown panel
        const { recentEvents, totalGain, totalLoss } = await getRecentContributingEvents(
            user._id,
            { limit: 10 }
        );

        return res.status(200).json({
            success: true,
            trustScore: {
                current:   user.trustScore,
                level:     level.label,
                description: level.description,
            },
            breakdown: {
                recentGain: totalGain,
                recentLoss: totalLoss,
                recentEvents,
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Server error fetching trust score.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET MY TRUST HISTORY
// GET /api/trust/me/history?page=1&limit=20
// Protected — paginated log of the user's own trust events
// ─────────────────────────────────────────
const getMyTrustHistory = async (req, res) => {
    try {
        const { page = 1, limit = 20 } = req.query;

        const { logs, pagination } = await getTrustScoreHistory(req.user.id, {
            page,
            limit,
        });

        return res.status(200).json({
            success: true,
            pagination,
            history: logs,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Server error fetching trust history.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET USER TRUST SCORE
// GET /api/trust/admin/users/:userId
// Protected + adminOnly
// ─────────────────────────────────────────
const getUserTrustScore = async (req, res) => {
    try {
        const { userId } = req.params;

        const user = await User.findById(userId).select(
            "name email trustScore riskScore isLocked failedLoginAttempts lastLoginAt"
        );

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const level = getTrustLevel(user.trustScore);

        const { recentEvents, totalGain, totalLoss } = await getRecentContributingEvents(
            user._id,
            { limit: 10 }
        );

        return res.status(200).json({
            success: true,
            user: {
                id:    user._id,
                name:  user.name,
                email: user.email,
                isLocked:            user.isLocked,
                failedLoginAttempts: user.failedLoginAttempts,
                lastLoginAt:         user.lastLoginAt,
            },
            trustScore: {
                current:     user.trustScore,
                level:       level.label,
                description: level.description,
            },
            breakdown: {
                recentGain:   totalGain,
                recentLoss:   totalLoss,
                recentEvents,
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Server error fetching user trust score.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET SYSTEM TRUST OVERVIEW
// GET /api/trust/admin/overview
// Protected + adminOnly
//
// Returns:
//   - Distribution of users across all four trust bands
//   - Average trust score across all users
//   - List of the N lowest-trust users (configurable via ?limit=)
// ─────────────────────────────────────────
const getSystemTrustOverview = async (req, res) => {
    try {
        // Number of lowest-trust users to surface — default 10, max 50
        const bottomLimit = Math.min(parseInt(req.query.limit) || 10, 50);

        // ── Aggregation: bucket users into trust bands ────────────────
        // Band boundaries from TRUST_BANDS constants:
        //   poor:      0-39
        //   fair:      40-59
        //   good:      60-79
        //   excellent: 80-100
        const bandDistribution = await User.aggregate([
            {
                $facet: {
                    excellent: [
                        { $match: { trustScore: { $gte: 80 } } },
                        { $count: "count" },
                    ],
                    good: [
                        { $match: { trustScore: { $gte: 60, $lt: 80 } } },
                        { $count: "count" },
                    ],
                    fair: [
                        { $match: { trustScore: { $gte: 40, $lt: 60 } } },
                        { $count: "count" },
                    ],
                    poor: [
                        { $match: { trustScore: { $lt: 40 } } },
                        { $count: "count" },
                    ],
                    average: [
                        { $group: { _id: null, avg: { $avg: "$trustScore" } } },
                    ],
                    total: [
                        { $count: "count" },
                    ],
                },
            },
        ]);

        const facet      = bandDistribution[0];
        const totalUsers = facet.total[0]?.count || 0;
        const avgScore   = facet.average[0]?.avg != null
            ? parseFloat(facet.average[0].avg.toFixed(2))
            : null;

        const distribution = {
            excellent: facet.excellent[0]?.count || 0,
            good:      facet.good[0]?.count      || 0,
            fair:      facet.fair[0]?.count      || 0,
            poor:      facet.poor[0]?.count      || 0,
        };

        // Compute percentages for each band
        const percentages = {};
        for (const band of Object.keys(distribution)) {
            percentages[band] = totalUsers > 0
                ? parseFloat(((distribution[band] / totalUsers) * 100).toFixed(1))
                : 0;
        }

        // ── Bottom-N lowest trust users ───────────────────────────────
        const lowestTrustUsers = await User.find()
            .sort({ trustScore: 1 })
            .limit(bottomLimit)
            .select("name email trustScore riskScore isLocked lastLoginAt")
            .lean();

        // Attach trust level label to each
        const { getTrustLevel: getLevel } = require("../services/trustScoreService");
        const lowestWithLevel = lowestTrustUsers.map((u) => ({
            ...u,
            trustLevel: getLevel(u.trustScore).label,
        }));

        return res.status(200).json({
            success: true,
            overview: {
                totalUsers,
                averageTrustScore: avgScore,
                distribution,
                percentages,
            },
            lowestTrustUsers: lowestWithLevel,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Server error fetching system trust overview.",
            error: error.message,
        });
    }
};

module.exports = {
    getMyTrustScore,
    getMyTrustHistory,
    getUserTrustScore,
    getSystemTrustOverview,
};
