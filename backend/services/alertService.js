const mongoose    = require("mongoose");
const SecurityAlert = require("../models/SecurityAlert");

// ─────────────────────────────────────────
// HELPER — Build a filter query from optional params
// Shared between user-facing and admin queries
// ─────────────────────────────────────────
const buildAlertFilter = ({ userId, alertType, severity, isResolved, isRead } = {}) => {
    const filter = {};

    if (userId)     filter.userId     = userId;
    if (alertType)  filter.alertType  = alertType;
    if (severity)   filter.severity   = severity;

    // Boolean filters — only apply when the query string param is explicitly set
    if (isResolved !== undefined && isResolved !== "")
        filter.isResolved = isResolved === "true" || isResolved === true;

    if (isRead !== undefined && isRead !== "")
        filter.isRead = isRead === "true" || isRead === true;

    return filter;
};

// ─────────────────────────────────────────
// HELPER — Normalise pagination params
// ─────────────────────────────────────────
const parsePagination = ({ page, limit }) => {
    const safePage  = Math.max(parseInt(page)  || 1, 1);
    const safeLimit = Math.min(parseInt(limit) || 20, 100);
    const skip      = (safePage - 1) * safeLimit;
    return { safePage, safeLimit, skip };
};

// ─────────────────────────────────────────
// GET ALERTS FOR A SPECIFIC USER
// Called by the user-facing controller
// ─────────────────────────────────────────
const getAlertsForUser = async (userId, { page, limit, alertType, severity, isResolved } = {}) => {
    const { safePage, safeLimit, skip } = parsePagination({ page, limit });
    const filter = buildAlertFilter({ userId, alertType, severity, isResolved });

    const [alerts, total] = await Promise.all([
        SecurityAlert.find(filter)
            .sort({ triggeredAt: -1 })
            .skip(skip)
            .limit(safeLimit)
            .lean(),
        SecurityAlert.countDocuments(filter),
    ]);

    return {
        alerts,
        pagination: {
            total,
            page:  safePage,
            pages: Math.ceil(total / safeLimit),
            limit: safeLimit,
        },
    };
};

// ─────────────────────────────────────────
// GET ALL ALERTS (Admin)
// Supports all filter dimensions + populate user info
// ─────────────────────────────────────────
const getAllAlerts = async ({ page, limit, alertType, severity, isResolved, isRead } = {}) => {
    const { safePage, safeLimit, skip } = parsePagination({ page, limit });
    const filter = buildAlertFilter({ alertType, severity, isResolved, isRead });

    const [alerts, total] = await Promise.all([
        SecurityAlert.find(filter)
            .sort({ triggeredAt: -1 })
            .skip(skip)
            .limit(safeLimit)
            // Populate just the user name + email — admins don't need the full doc
            .populate("userId", "name email role")
            .lean(),
        SecurityAlert.countDocuments(filter),
    ]);

    return {
        alerts,
        pagination: {
            total,
            page:  safePage,
            pages: Math.ceil(total / safeLimit),
            limit: safeLimit,
        },
    };
};

// ─────────────────────────────────────────
// MARK ALERT AS READ
// Any authenticated user can only mark their own alerts.
// Controller is responsible for ownership check before calling this.
// ─────────────────────────────────────────
const markAlertAsRead = async (alertId) => {
    const alert = await SecurityAlert.findByIdAndUpdate(
        alertId,
        { isRead: true },
        { new: true }
    );

    if (!alert) return { success: false, message: "Alert not found." };

    return { success: true, alert };
};

// ─────────────────────────────────────────
// RESOLVE ALERT (Admin only)
// Marks as resolved, records who resolved it and when
// ─────────────────────────────────────────
const resolveAlert = async (alertId, adminId, resolvedNote = null) => {
    const alert = await SecurityAlert.findById(alertId);

    if (!alert) return { success: false, message: "Alert not found." };

    if (alert.isResolved) {
        return {
            success: false,
            message: "Alert is already resolved.",
            resolvedAt: alert.resolvedAt,
        };
    }

    alert.isResolved  = true;
    alert.resolvedAt  = new Date();
    alert.resolvedBy  = adminId;
    alert.resolvedNote = resolvedNote || null;
    alert.isRead      = true; // A resolved alert is implicitly read

    await alert.save();

    return { success: true, alert };
};

// ─────────────────────────────────────────
// GET ALERT STATS (Admin dashboard)
// Aggregate counts across every useful dimension
// ─────────────────────────────────────────
const getAlertStats = async () => {
    const last24h  = new Date(Date.now() - 24  * 60 * 60 * 1000);
    const last7d   = new Date(Date.now() - 7   * 24 * 60 * 60 * 1000);

    // ── Run all counts in parallel ─────────────────────────────────
    const [
        totalAlerts,
        unresolvedCount,
        unreadCount,
        last24hCount,
        last7dCount,
        byTypeRaw,
        bySeverityRaw,
        criticalUnresolved,
    ] = await Promise.all([
        SecurityAlert.countDocuments({}),
        SecurityAlert.countDocuments({ isResolved: false }),
        SecurityAlert.countDocuments({ isRead: false }),
        SecurityAlert.countDocuments({ triggeredAt: { $gte: last24h } }),
        SecurityAlert.countDocuments({ triggeredAt: { $gte: last7d } }),

        // Count grouped by alertType
        SecurityAlert.aggregate([
            { $group: { _id: "$alertType", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
        ]),

        // Count grouped by severity
        SecurityAlert.aggregate([
            { $group: { _id: "$severity", count: { $sum: 1 } } },
            { $sort: { count: -1 } },
        ]),

        // Unresolved critical + high alerts (most urgent)
        SecurityAlert.countDocuments({
            severity:   { $in: ["critical", "high"] },
            isResolved: false,
        }),
    ]);

    // Reshape aggregation arrays into flat objects for easy front-end use
    const byType     = byTypeRaw.reduce((acc, { _id, count }) => { if (_id) acc[_id] = count; return acc; }, {});
    const bySeverity = bySeverityRaw.reduce((acc, { _id, count }) => { if (_id) acc[_id] = count; return acc; }, {});

    return {
        totalAlerts,
        unresolvedCount,
        unreadCount,
        criticalUnresolved,
        last24hCount,
        last7dCount,
        byType,
        bySeverity,
        resolutionRate: totalAlerts > 0
            ? parseFloat(((totalAlerts - unresolvedCount) / totalAlerts * 100).toFixed(1))
            : 0,
    };
};

module.exports = {
    getAlertsForUser,
    getAllAlerts,
    markAlertAsRead,
    resolveAlert,
    getAlertStats,
};
