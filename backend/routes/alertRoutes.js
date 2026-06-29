const express = require("express");
const router  = express.Router();
const { protect, adminOnly } = require("../middlewares/authMiddleware");
const {
    getMyAlerts,
    markMyAlertRead,
    getAllAlertsAdmin,
    resolveAlertAdmin,
    getAlertStatsAdmin,
} = require("../controllers/alertController");

// ─────────────────────────────────────────
// USER ROUTES — authenticated user's own alerts
// Base: /api/alerts
// ─────────────────────────────────────────

// GET /api/alerts/me?page=1&limit=20&alertType=&severity=&isResolved=
router.get("/me", protect, getMyAlerts);

// PUT /api/alerts/:alertId/read
router.put("/:alertId/read", protect, markMyAlertRead);

// ─────────────────────────────────────────
// ADMIN ROUTES
// Base: /api/alerts/admin
// ─────────────────────────────────────────

// GET /api/alerts/admin/stats
// NOTE: /admin/stats must be declared BEFORE /admin/:alertId/resolve
// to prevent Express matching "stats" as an :alertId param
router.get("/admin/stats", protect, adminOnly, getAlertStatsAdmin);

// GET /api/alerts/admin?page=1&limit=20&alertType=&severity=&isResolved=&isRead=
router.get("/admin", protect, adminOnly, getAllAlertsAdmin);

// PUT /api/alerts/admin/:alertId/resolve
router.put("/admin/:alertId/resolve", protect, adminOnly, resolveAlertAdmin);

module.exports = router;
