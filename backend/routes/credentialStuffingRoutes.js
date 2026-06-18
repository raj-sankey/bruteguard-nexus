const express = require("express");
const router = express.Router();

const {
    checkMyIPStatus,
    getCSStats,
    getAllBlockedIPs,
    manuallyBlockIP,
    unblockIP,
    getIPDetails,
    getCSAlerts,
} = require("../controllers/credentialStuffingController");

const { protect, adminOnly } = require("../middlewares/authMiddleware");

// ─────────────────────────────────────────
// USER ROUTES
// ─────────────────────────────────────────
router.get("/ip/check", protect, checkMyIPStatus);

// ─────────────────────────────────────────
// ADMIN ROUTES
// ─────────────────────────────────────────
router.get("/admin/stats", protect, adminOnly, getCSStats);
router.get("/admin/blocked", protect, adminOnly, getAllBlockedIPs);
router.get("/admin/alerts", protect, adminOnly, getCSAlerts);
router.get("/admin/ip/:ipAddress", protect, adminOnly, getIPDetails);
router.post("/admin/block", protect, adminOnly, manuallyBlockIP);
router.put("/admin/unblock/:ipAddress", protect, adminOnly, unblockIP);

module.exports = router;