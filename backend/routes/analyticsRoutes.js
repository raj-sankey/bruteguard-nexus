const express = require("express");
const router  = express.Router();
const { protect, adminOnly } = require("../middlewares/authMiddleware");
const {
    getMyRiskTrend,
    getMyTrustTrend,
    getSystemRiskTrend,
    getLoginStatsAdmin,
    getAttackStatsAdmin,
} = require("../controllers/analyticsController");

// ─────────────────────────────────────────
// USER ROUTES — scoped to authenticated user
// Base: /api/analytics
// ─────────────────────────────────────────

// GET /api/analytics/me/risk-trend?days=30
router.get("/me/risk-trend",   protect, getMyRiskTrend);

// GET /api/analytics/me/trust-trend?days=30
router.get("/me/trust-trend",  protect, getMyTrustTrend);

// ─────────────────────────────────────────
// ADMIN ROUTES — system-wide analytics
// Base: /api/analytics/admin
// ─────────────────────────────────────────

// GET /api/analytics/admin/risk-trend?days=30
router.get("/admin/risk-trend",    protect, adminOnly, getSystemRiskTrend);

// GET /api/analytics/admin/login-stats?period=daily|weekly|monthly&days=30
router.get("/admin/login-stats",   protect, adminOnly, getLoginStatsAdmin);

// GET /api/analytics/admin/attack-stats?days=30
router.get("/admin/attack-stats",  protect, adminOnly, getAttackStatsAdmin);

module.exports = router;
