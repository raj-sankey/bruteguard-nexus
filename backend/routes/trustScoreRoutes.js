const express = require("express");
const router  = express.Router();
const { protect, adminOnly } = require("../middlewares/authMiddleware");
const {
    getMyTrustScore,
    getMyTrustHistory,
    getUserTrustScore,
    getSystemTrustOverview,
} = require("../controllers/trustScoreController");

// ─────────────────────────────────────────
// USER ROUTES — authenticated user's own data
// Base: /api/trust
// ─────────────────────────────────────────

// GET /api/trust/me
// Returns current score, trust level, and breakdown of recent events
router.get("/me", protect, getMyTrustScore);

// GET /api/trust/me/history?page=1&limit=20
// Returns paginated audit log of trust-affecting events
router.get("/me/history", protect, getMyTrustHistory);

// ─────────────────────────────────────────
// ADMIN ROUTES — require protect + adminOnly
// Base: /api/trust/admin
// ─────────────────────────────────────────

// GET /api/trust/admin/overview?limit=10
// System-wide trust band distribution + lowest-trust users
router.get("/admin/overview", protect, adminOnly, getSystemTrustOverview);

// GET /api/trust/admin/users/:userId
// Specific user's trust score detail (same shape as /me but any user)
router.get("/admin/users/:userId", protect, adminOnly, getUserTrustScore);

module.exports = router;
