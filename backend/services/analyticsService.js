const mongoose      = require("mongoose");
const LoginAttempt  = require("../models/LoginAttempt");
const SecurityAlert = require("../models/SecurityAlert");
const BlockedIP     = require("../models/BlockedIP");
const TrustScoreLog = require("../models/TrustScoreLog");

// ─────────────────────────────────────────
// HELPER — Generate an array of ISO date strings for the last N days
// Used to ensure every day appears in chart output even if it has zero data
// ─────────────────────────────────────────
const generateDateRange = (days) => {
    const dates = [];
    for (let i = days - 1; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        dates.push(d.toISOString().slice(0, 10)); // "YYYY-MM-DD"
    }
    return dates;
};

// ─────────────────────────────────────────
// HELPER — Merge aggregation result into a zero-padded date-indexed map
// Ensures chart series have a value for every day (no missing gaps)
// ─────────────────────────────────────────
const padDates = (dateRange, data, keyField, valueField) => {
    const map = {};
    data.forEach((d) => { map[d[keyField]] = d[valueField]; });
    return dateRange.map((date) => ({ date, value: map[date] || 0 }));
};

// ─────────────────────────────────────────
// HELPER — Get date-grouping $dateToString format for a period
// ─────────────────────────────────────────
const getGroupFormat = (period) => {
    switch (period) {
        case "monthly": return "%Y-%m";
        case "weekly":  return "%Y-%W"; // ISO week number
        default:        return "%Y-%m-%d"; // daily (default)
    }
};

// ─────────────────────────────────────────
// HELPER — Build $match date range filter
// ─────────────────────────────────────────
const dateRangeMatch = (field, days) => ({
    [field]: { $gte: new Date(Date.now() - days * 24 * 60 * 60 * 1000) },
});

// ─────────────────────────────────────────
// RISK TREND
// Daily average risk score over the last N days
// Optionally scoped to a single user (userId = null → system-wide)
//
// Output shape (Recharts-ready):
//   [{ date: "2025-06-01", value: 42.5 }, ...]
// ─────────────────────────────────────────
const getRiskTrend = async ({ userId = null, days = 30 } = {}) => {
    const safeDays  = Math.min(parseInt(days) || 30, 365);
    const dateRange = generateDateRange(safeDays);

    const match = {
        ...dateRangeMatch("attemptedAt", safeDays),
        riskScore: { $ne: null }, // Only records that have a risk score
    };

    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
        match.userId = new mongoose.Types.ObjectId(userId);
    }

    const raw = await LoginAttempt.aggregate([
        { $match: match },
        {
            $group: {
                _id: {
                    $dateToString: { format: "%Y-%m-%d", date: "$attemptedAt" },
                },
                avgRisk:    { $avg: "$riskScore" },
                maxRisk:    { $max: "$riskScore" },
                sampleSize: { $sum: 1 },
            },
        },
        { $sort: { _id: 1 } },
        {
            $project: {
                date:       "$_id",
                value:      { $round: ["$avgRisk", 2] },
                max:        { $round: ["$maxRisk", 2] },
                sampleSize: 1,
                _id:        0,
            },
        },
    ]);

    // Pad missing days with 0 (Chart will render a flat line, not break)
    const byDate = {};
    raw.forEach((r) => { byDate[r.date] = r; });

    const series = dateRange.map((date) => byDate[date] || { date, value: 0, max: 0, sampleSize: 0 });

    return { series, days: safeDays, scope: userId ? "user" : "system" };
};

// ─────────────────────────────────────────
// LOGIN STATS
// Count of successful vs. failed logins grouped by period
// Optionally scoped to a user
//
// Output shape (Recharts-ready — two series on one chart):
//   [{ date: "2025-06-01", success: 12, failed: 3, total: 15 }, ...]
// ─────────────────────────────────────────
const getLoginStats = async ({ userId = null, period = "daily", days = 30 } = {}) => {
    const safeDays  = Math.min(parseInt(days) || 30, 365);
    const format    = getGroupFormat(period);

    const match = { ...dateRangeMatch("attemptedAt", safeDays) };

    if (userId && mongoose.Types.ObjectId.isValid(userId)) {
        match.userId = new mongoose.Types.ObjectId(userId);
    }

    const raw = await LoginAttempt.aggregate([
        { $match: match },
        {
            $group: {
                _id: {
                    period: { $dateToString: { format, date: "$attemptedAt" } },
                },
                success: { $sum: { $cond: ["$success", 1, 0] } },
                failed:  { $sum: { $cond: ["$success", 0, 1] } },
                total:   { $sum: 1 },
            },
        },
        { $sort: { "_id.period": 1 } },
        {
            $project: {
                date:    "$_id.period",
                success: 1,
                failed:  1,
                total:   1,
                _id:     0,
            },
        },
    ]);

    // For daily, pad with zeros for missing dates so Recharts doesn't skip gaps
    if (period === "daily") {
        const dateRange = generateDateRange(safeDays);
        const byDate    = {};
        raw.forEach((r) => { byDate[r.date] = r; });
        const series = dateRange.map(
            (date) => byDate[date] || { date, success: 0, failed: 0, total: 0 }
        );
        return { series, period, days: safeDays, scope: userId ? "user" : "system" };
    }

    return { series: raw, period, days: safeDays, scope: userId ? "user" : "system" };
};

// ─────────────────────────────────────────
// ATTACK STATS
// Daily counts of three attack alert types + blocked IPs over time
// Always system-wide (no per-user scope)
//
// Output shape:
//   {
//     alertSeries: [{ date, brute_force, credential_stuffing, high_risk_login, total }, ...],
//     blockedIPSeries: [{ date, value }, ...],   // IPs blocked per day
//     totals: { brute_force, credential_stuffing, high_risk_login, blockedIPs }
//   }
// ─────────────────────────────────────────
const getAttackStats = async ({ days = 30 } = {}) => {
    const safeDays  = Math.min(parseInt(days) || 30, 365);
    const dateRange = generateDateRange(safeDays);

    const alertMatch = {
        alertType: { $in: ["brute_force", "credential_stuffing", "high_risk_login"] },
        ...dateRangeMatch("triggeredAt", safeDays),
    };

    const [alertsRaw, blockedIPsRaw] = await Promise.all([
        // ── Alert counts grouped by day + type ────────────────────
        SecurityAlert.aggregate([
            { $match: alertMatch },
            {
                $group: {
                    _id: {
                        date: { $dateToString: { format: "%Y-%m-%d", date: "$triggeredAt" } },
                        type: "$alertType",
                    },
                    count: { $sum: 1 },
                },
            },
            { $sort: { "_id.date": 1 } },
        ]),

        // ── BlockedIPs created per day ─────────────────────────────
        BlockedIP.aggregate([
            { $match: dateRangeMatch("createdAt", safeDays) },
            {
                $group: {
                    _id: {
                        $dateToString: { format: "%Y-%m-%d", date: "$createdAt" },
                    },
                    count: { $sum: 1 },
                },
            },
            { $sort: { _id: 1 } },
        ]),
    ]);

    // ── Pivot alert results by date+type → flat objects per date ──
    const alertByDate = {};
    alertsRaw.forEach(({ _id: { date, type }, count }) => {
        if (!alertByDate[date]) {
            alertByDate[date] = { date, brute_force: 0, credential_stuffing: 0, high_risk_login: 0, total: 0 };
        }
        alertByDate[date][type]  += count;
        alertByDate[date].total  += count;
    });

    const alertSeries = dateRange.map(
        (date) => alertByDate[date] || { date, brute_force: 0, credential_stuffing: 0, high_risk_login: 0, total: 0 }
    );

    // ── Pad blocked IPs ───────────────────────────────────────────
    const blockedIPSeries = padDates(dateRange, blockedIPsRaw, "_id", "count");

    // ── All-time totals ────────────────────────────────────────────
    const [totalBF, totalCS, totalHR, totalBlockedIPs] = await Promise.all([
        SecurityAlert.countDocuments({ alertType: "brute_force" }),
        SecurityAlert.countDocuments({ alertType: "credential_stuffing" }),
        SecurityAlert.countDocuments({ alertType: "high_risk_login" }),
        BlockedIP.countDocuments({}),
    ]);

    return {
        alertSeries,
        blockedIPSeries,
        totals: {
            brute_force:          totalBF,
            credential_stuffing:  totalCS,
            high_risk_login:      totalHR,
            totalBlockedIPs,
        },
        days: safeDays,
    };
};

// ─────────────────────────────────────────
// TRUST SCORE TREND
// Point-in-time trustScore trend derived from TrustScoreLog
//
// NOTE ON DATA SOURCE:
//   We use TrustScoreLog (Phase 9 dedicated model) rather than
//   LoginAttempt.riskScore. TrustScoreLog stores scoreAfter for
//   every delta event — so grouping by date and taking the last
//   scoreAfter per day gives a true end-of-day trust score snapshot.
//   This is NOT an approximation; it is derived from the actual stored values.
//
// Output shape (Recharts-ready):
//   [{ date: "2025-06-01", value: 78 }, ...]
// ─────────────────────────────────────────
const getTrustScoreTrend = async ({ userId, days = 30 } = {}) => {
    const safeDays  = Math.min(parseInt(days) || 30, 365);
    const dateRange = generateDateRange(safeDays);

    if (!userId || !mongoose.Types.ObjectId.isValid(userId)) {
        throw new Error("A valid userId is required for getTrustScoreTrend.");
    }

    const raw = await TrustScoreLog.aggregate([
        {
            $match: {
                userId: new mongoose.Types.ObjectId(userId),
                ...dateRangeMatch("loggedAt", safeDays),
            },
        },
        {
            $group: {
                _id: {
                    $dateToString: { format: "%Y-%m-%d", date: "$loggedAt" },
                },
                // The last log entry of the day reflects end-of-day score
                scoreAfter: { $last: "$scoreAfter" },
                eventCount: { $sum: 1 },
            },
        },
        { $sort: { _id: 1 } },
        {
            $project: {
                date:       "$_id",
                value:      "$scoreAfter",
                eventCount: 1,
                _id:        0,
            },
        },
    ]);

    // For days with no log events, carry forward the last known score
    // This gives a continuous line on the chart rather than dropping to 0
    const byDate = {};
    raw.forEach((r) => { byDate[r.date] = r; });

    let lastKnown = null;
    const series = dateRange.map((date) => {
        if (byDate[date]) {
            lastKnown = byDate[date].value;
            return byDate[date];
        }
        // Carry forward — if we have a prior value, use it; otherwise null
        return { date, value: lastKnown, eventCount: 0 };
    });

    return { series, days: safeDays, userId };
};

module.exports = {
    getRiskTrend,
    getLoginStats,
    getAttackStats,
    getTrustScoreTrend,
};
