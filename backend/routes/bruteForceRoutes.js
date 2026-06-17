const express = require("express");
const router = express.Router();

const {
    getMyLockStatus,
    getMyFailedAttempts,
    getBruteForceAdminStats,
    getLockedAccounts,
    unlockUserAccount,
    lockUserAccount,
    getBruteForceAlerts,
} = require("../controllers/bruteForceController");

const { protect, adminOnly } = require("../middlewares/authMiddleware");

// ─────────────────────────────────────────
// USER ROUTES
// ─────────────────────────────────────────
router.get("/status", protect, getMyLockStatus);
router.get("/attempts", protect, getMyFailedAttempts);

// ─────────────────────────────────────────
// ADMIN ROUTES
// ─────────────────────────────────────────
router.get("/admin/stats", protect, adminOnly, getBruteForceAdminStats);
router.get("/admin/locked", protect, adminOnly, getLockedAccounts);
router.get("/admin/alerts", protect, adminOnly, getBruteForceAlerts);
router.put("/admin/unlock/:userId", protect, adminOnly, unlockUserAccount);
router.put("/admin/lock/:userId", protect, adminOnly, lockUserAccount);

module.exports = router;