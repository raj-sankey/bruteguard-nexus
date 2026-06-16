const express = require("express");
const router = express.Router();

const {
    submitBiometrics,
    getMyBaseline,
    getBiometricHistory,
    resetBaseline,
    getUserBiometricHistory,
} = require("../controllers/biometricController");

const { protect, adminOnly } = require("../middlewares/authMiddleware");

// ─────────────────────────────────────────
// USER ROUTES (protected)
// ─────────────────────────────────────────
router.post("/submit", protect, submitBiometrics);
router.get("/baseline", protect, getMyBaseline);
router.get("/history", protect, getBiometricHistory);
router.delete("/baseline/reset", protect, resetBaseline);

// ─────────────────────────────────────────
// ADMIN ROUTES
// ─────────────────────────────────────────
router.get("/admin/:userId/history", protect, adminOnly, getUserBiometricHistory);

module.exports = router;