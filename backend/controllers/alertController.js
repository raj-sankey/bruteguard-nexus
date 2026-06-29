const mongoose      = require("mongoose");
const SecurityAlert = require("../models/SecurityAlert");
const {
    getAlertsForUser,
    getAllAlerts,
    markAlertAsRead,
    resolveAlert,
    getAlertStats,
} = require("../services/alertService");

// ─────────────────────────────────────────
// GET MY ALERTS
// GET /api/alerts/me
// Protected — authenticated user sees only their own alerts
// Query params: ?page=1&limit=20&alertType=brute_force&severity=high&isResolved=false
// ─────────────────────────────────────────
const getMyAlerts = async (req, res) => {
    try {
        const { page, limit, alertType, severity, isResolved } = req.query;

        const result = await getAlertsForUser(req.user.id, {
            page,
            limit,
            alertType,
            severity,
            isResolved,
        });

        return res.status(200).json({
            success: true,
            ...result,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching your alerts.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// MARK MY ALERT AS READ
// PUT /api/alerts/:alertId/read
// Protected — user can only read their own alerts
// ─────────────────────────────────────────
const markMyAlertRead = async (req, res) => {
    try {
        const { alertId } = req.params;

        // Validate ObjectId format early
        if (!mongoose.Types.ObjectId.isValid(alertId)) {
            return res.status(400).json({ success: false, message: "Invalid alert ID." });
        }

        // Ownership check — fetch alert first, verify userId matches
        const alert = await SecurityAlert.findById(alertId);

        if (!alert) {
            return res.status(404).json({ success: false, message: "Alert not found." });
        }

        // Prevent users from marking other users' alerts as read
        if (alert.userId && alert.userId.toString() !== req.user.id.toString()) {
            return res.status(403).json({
                success: false,
                message: "You can only update your own alerts.",
            });
        }

        const result = await markAlertAsRead(alertId);

        return res.status(200).json({
            success: true,
            message: "Alert marked as read.",
            alert: result.alert,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error updating alert.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET ALL ALERTS
// GET /api/alerts/admin
// Protected + adminOnly
// Query params: ?page=1&limit=20&alertType=&severity=&isResolved=&isRead=
// ─────────────────────────────────────────
const getAllAlertsAdmin = async (req, res) => {
    try {
        const { page, limit, alertType, severity, isResolved, isRead } = req.query;

        const result = await getAllAlerts({
            page,
            limit,
            alertType,
            severity,
            isResolved,
            isRead,
        });

        return res.status(200).json({
            success: true,
            ...result,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching alerts.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — RESOLVE AN ALERT
// PUT /api/alerts/admin/:alertId/resolve
// Protected + adminOnly
// Body: { note: "Optional resolution note" }
// ─────────────────────────────────────────
const resolveAlertAdmin = async (req, res) => {
    try {
        const { alertId } = req.params;
        const { note }    = req.body;
        const adminId     = req.user.id;

        if (!mongoose.Types.ObjectId.isValid(alertId)) {
            return res.status(400).json({ success: false, message: "Invalid alert ID." });
        }

        const result = await resolveAlert(alertId, adminId, note || null);

        if (!result.success) {
            return res.status(400).json({
                success: false,
                message: result.message,
                resolvedAt: result.resolvedAt || null,
            });
        }

        return res.status(200).json({
            success: true,
            message: "Alert resolved successfully.",
            alert: result.alert,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error resolving alert.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET ALERT STATISTICS
// GET /api/alerts/admin/stats
// Protected + adminOnly
// ─────────────────────────────────────────
const getAlertStatsAdmin = async (req, res) => {
    try {
        const stats = await getAlertStats();

        return res.status(200).json({
            success: true,
            stats,
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Error fetching alert statistics.",
            error: error.message,
        });
    }
};

module.exports = {
    getMyAlerts,
    markMyAlertRead,
    getAllAlertsAdmin,
    resolveAlertAdmin,
    getAlertStatsAdmin,
};
