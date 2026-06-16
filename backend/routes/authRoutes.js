const express = require("express");
const router = express.Router();
const rateLimit = require("express-rate-limit");

const {
    register,
    login,
    getProfile,
    changePassword,
} = require("../controllers/authController");

const { protect } = require("../middlewares/authMiddleware");

// ─────────────────────────────────────────
// AUTH-SPECIFIC RATE LIMITERS
// ─────────────────────────────────────────

// Strict limiter for login — 10 attempts per 15 min
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: {
        success: false,
        message: "Too many login attempts. Please try again after 15 minutes.",
    },
    standardHeaders: true,
    legacyHeaders: false,
});

// Moderate limiter for register
const registerLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 5,
    message: {
        success: false,
        message: "Too many accounts created from this IP. Try again after an hour.",
    },
});

// ─────────────────────────────────────────
// PUBLIC ROUTES
// ─────────────────────────────────────────
router.post("/register", registerLimiter, register);
router.post("/login", loginLimiter, login);

// ─────────────────────────────────────────
// PROTECTED ROUTES
// ─────────────────────────────────────────
router.get("/profile", protect, getProfile);
router.put("/change-password", protect, changePassword);

module.exports = router;