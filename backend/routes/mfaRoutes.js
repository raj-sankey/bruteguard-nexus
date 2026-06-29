const express = require("express");
const router = express.Router();
const rateLimit = require("express-rate-limit");

const {
    requestOTP,
    verifyOTP,
    resendOTP,
    getMFAStatus,
    getMFAStats,
} = require("../controllers/mfaController");

const { protect, adminOnly } = require("../middlewares/authMiddleware");

// ─────────────────────────────────────────
// OTP RATE LIMITERS
// ─────────────────────────────────────────

// Max 5 OTP requests per 15 minutes per IP
const otpRequestLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    message: {
        success: false,
        message: "Too many OTP requests. Please try again after 15 minutes.",
    },
});

// Max 10 OTP verify attempts per 15 minutes
const otpVerifyLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: {
        success: false,
        message: "Too many OTP verification attempts. Please try again later.",
    },
});

// ─────────────────────────────────────────
// PUBLIC ROUTES
// ─────────────────────────────────────────
router.post("/send-otp", otpRequestLimiter, requestOTP);
router.post("/verify-otp", otpVerifyLimiter, verifyOTP);
router.post("/resend-otp", otpRequestLimiter, resendOTP);

// ─────────────────────────────────────────
// PROTECTED ROUTES
// ─────────────────────────────────────────
router.get("/status", protect, getMFAStatus);

// ─────────────────────────────────────────
// ADMIN ROUTES
// ─────────────────────────────────────────
router.get("/admin/stats", protect, adminOnly, getMFAStats);

module.exports = router;