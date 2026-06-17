const express = require("express");
const router = express.Router();

const {
    getMyRiskScore,
    getMyRiskHistory,
    getRiskConfig,
    getSystemRiskSummary,
    getUserRiskDetails,
} = require("../controllers/riskController");

const { protect, adminOnly } = require("../middlewares/authMiddleware");

// ─────────────────────────────────────────
// USER ROUTES
// ─────────────────────────────────────────
router.get("/me", protect, getMyRiskScore);
router.get("/history", protect, getMyRiskHistory);

// ─────────────────────────────────────────
// ADMIN ROUTES
// ─────────────────────────────────────────
router.get("/config", protect, adminOnly, getRiskConfig);
router.get("/admin/summary", protect, adminOnly, getSystemRiskSummary);
router.get("/admin/:userId", protect, adminOnly, getUserRiskDetails);

module.exports = router;