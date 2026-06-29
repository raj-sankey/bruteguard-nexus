const mongoose = require("mongoose");
const {
    getAllUsers,
    getUserDetailById,
    getAllLoginAttempts,
    getSystemWideStats,
} = require("../services/adminService");

// ─────────────────────────────────────────
// Re-export from bruteForceController
//
// lock/unlock already fully implemented in Phase 6 under:
//   PUT /api/bruteforce/admin/lock/:userId
//   PUT /api/bruteforce/admin/unlock/:userId
//
// Those handlers are re-wired here under the /api/admin namespace
// so the admin panel has a single coherent base URL, while avoiding
// any duplication of business logic.
// ─────────────────────────────────────────
const {
    lockUserAccount,
    unlockUserAccount,
} = require("./bruteForceController");

// ─────────────────────────────────────────
// GET ALL USERS
// GET /api/admin/users
// Query: ?page=1&limit=20&search=&role=&isLocked=&sortBy=createdAt
// ─────────────────────────────────────────
const getAllUsersAdmin = async (req, res) => {
    try {
        const { page, limit, search, role, isLocked, sortBy } = req.query;

        const result = await getAllUsers({ page, limit, search, role, isLocked, sortBy });

        return res.status(200).json({
            success: true,
            ...result,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching users.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET USER BY ID (Full detail view)
// GET /api/admin/users/:userId
// ─────────────────────────────────────────
const getUserByIdAdmin = async (req, res) => {
    try {
        const { userId } = req.params;

        if (!mongoose.Types.ObjectId.isValid(userId)) {
            return res.status(400).json({ success: false, message: "Invalid user ID." });
        }

        const detail = await getUserDetailById(userId);

        if (!detail) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        return res.status(200).json({
            success: true,
            ...detail,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching user detail.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET ALL LOGIN ATTEMPTS (Admin)
// GET /api/admin/login-attempts
// Query: ?page=1&limit=20&userId=&success=&riskLevel=&ipAddress=
// ─────────────────────────────────────────
const getAllLoginAttemptsAdmin = async (req, res) => {
    try {
        const { page, limit, userId, success, riskLevel, ipAddress } = req.query;

        const result = await getAllLoginAttempts({
            page,
            limit,
            userId,
            success,
            riskLevel,
            ipAddress,
        });

        return res.status(200).json({
            success: true,
            ...result,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching login attempts.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET SYSTEM STATS (Admin Dashboard Summary)
// GET /api/admin/stats
// ─────────────────────────────────────────
const getSystemStatsAdmin = async (req, res) => {
    try {
        const stats = await getSystemWideStats();

        return res.status(200).json({
            success: true,
            stats,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching system statistics.",
            error: error.message,
        });
    }
};

module.exports = {
    getAllUsersAdmin,
    getUserByIdAdmin,
    lockUserAccount,      // Re-exported from bruteForceController
    unlockUserAccount,    // Re-exported from bruteForceController
    getAllLoginAttemptsAdmin,
    getSystemStatsAdmin,
};
