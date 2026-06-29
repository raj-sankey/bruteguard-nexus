const express = require("express");
const router  = express.Router();
const { protect, adminOnly } = require("../middlewares/authMiddleware");
const {
    getAllUsersAdmin,
    getUserByIdAdmin,
    lockUserAccount,
    unlockUserAccount,
    getAllLoginAttemptsAdmin,
    getSystemStatsAdmin,
} = require("../controllers/adminController");

// ─────────────────────────────────────────
// ALL ROUTES REQUIRE protect + adminOnly
// No exceptions — every route below is admin-only
// Base: /api/admin
// ─────────────────────────────────────────

// ── SYSTEM STATS ──────────────────────────────────────────────────
// GET /api/admin/stats
router.get("/stats", protect, adminOnly, getSystemStatsAdmin);

// ── USER MANAGEMENT ───────────────────────────────────────────────

// GET /api/admin/users?page=&limit=&search=&role=&isLocked=&sortBy=
router.get("/users", protect, adminOnly, getAllUsersAdmin);

// GET /api/admin/users/:userId
router.get("/users/:userId", protect, adminOnly, getUserByIdAdmin);

// PUT /api/admin/users/:userId/lock   — body: { durationMinutes, reason }
router.put("/users/:userId/lock",   protect, adminOnly, lockUserAccount);

// PUT /api/admin/users/:userId/unlock
router.put("/users/:userId/unlock", protect, adminOnly, unlockUserAccount);

// ── LOGIN ATTEMPTS ────────────────────────────────────────────────

// GET /api/admin/login-attempts?page=&limit=&userId=&success=&riskLevel=&ipAddress=
router.get("/login-attempts", protect, adminOnly, getAllLoginAttemptsAdmin);

module.exports = router;
