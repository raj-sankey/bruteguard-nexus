const express = require("express");
const router = express.Router();

const {
    getMyContext,
    getLocationHistory,
    getMyDevices,
    resetKnownContext,
    getAdminUserContext,
} = require("../controllers/contextController");

const { protect, adminOnly } = require("../middlewares/authMiddleware");

// ─────────────────────────────────────────
// USER ROUTES
// ─────────────────────────────────────────
router.get("/me", protect, getMyContext);
router.get("/locations", protect, getLocationHistory);
router.get("/devices", protect, getMyDevices);
router.delete("/reset", protect, resetKnownContext);

// ─────────────────────────────────────────
// ADMIN ROUTES
// ─────────────────────────────────────────
router.get("/admin/:userId", protect, adminOnly, getAdminUserContext);

module.exports = router;