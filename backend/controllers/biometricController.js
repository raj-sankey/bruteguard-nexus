const LoginAttempt = require("../models/LoginAttempt");
const User = require("../models/User");
const {
    calculateBiometricAverages,
    updateBehavioralBaseline,
    compareBiometricsToBaseline,
} = require("../services/biometricService");

// ─────────────────────────────────────────
// SUBMIT BIOMETRIC DATA
// POST /api/biometrics/submit
// Protected — called right after login
// ─────────────────────────────────────────
const submitBiometrics = async (req, res) => {
    try {
        const { keystrokes, loginAttemptId } = req.body;
        const userId = req.user.id;

        if (!keystrokes || !Array.isArray(keystrokes) || keystrokes.length === 0) {
            return res.status(400).json({
                success: false,
                message: "Keystroke data is required.",
            });
        }

        // Calculate averages from raw keystrokes
        const biometricAverages = calculateBiometricAverages(keystrokes);

        // Get user's current baseline
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        // Compare current typing to baseline
        const { deviationScore, details } = compareBiometricsToBaseline(
            biometricAverages,
            user.behavioralBaseline
        );

        // Update baseline with new data (rolling average)
        const updatedBaseline = await updateBehavioralBaseline(userId, biometricAverages);

        // If loginAttemptId provided, update that LoginAttempt record
        if (loginAttemptId) {
            await LoginAttempt.findByIdAndUpdate(loginAttemptId, {
                "biometrics.typingSpeed": biometricAverages.typingSpeed,
                "biometrics.avgDwellTime": biometricAverages.avgDwellTime,
                "biometrics.avgFlightTime": biometricAverages.avgFlightTime,
                "biometrics.keystrokeCount": biometricAverages.keystrokeCount,
                "biometrics.keystrokes": keystrokes,
            });
        }

        return res.status(200).json({
            success: true,
            message: "Biometric data submitted and baseline updated.",
            data: {
                current: biometricAverages,
                baseline: updatedBaseline,
                deviationScore,
                deviationDetails: details,
                interpretation:
                    deviationScore < 30
                        ? "Normal — matches your typing pattern"
                        : deviationScore < 60
                            ? "Moderate deviation — slightly unusual"
                            : "High deviation — typing pattern does not match baseline",
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Server error submitting biometrics.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET MY BASELINE
// GET /api/biometrics/baseline
// Protected
// ─────────────────────────────────────────
const getMyBaseline = async (req, res) => {
    try {
        const user = await User.findById(req.user.id);

        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const { behavioralBaseline } = user;
        const sampleCount = behavioralBaseline.sampleCount || 0;

        return res.status(200).json({
            success: true,
            data: {
                baseline: behavioralBaseline,
                sampleCount,
                isEstablished: sampleCount >= 3,
                message:
                    sampleCount < 3
                        ? `Baseline needs ${3 - sampleCount} more login(s) to be established`
                        : "Baseline is established and active",
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Server error fetching baseline.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET MY LOGIN ATTEMPTS WITH BIOMETRICS
// GET /api/biometrics/history
// Protected
// ─────────────────────────────────────────
const getBiometricHistory = async (req, res) => {
    try {
        const userId = req.user.id;
        const limit = parseInt(req.query.limit) || 10;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        const attempts = await LoginAttempt.find({ userId })
            .sort({ attemptedAt: -1 })
            .skip(skip)
            .limit(limit)
            .select(
                "success biometrics.typingSpeed biometrics.avgDwellTime biometrics.avgFlightTime biometrics.keystrokeCount riskScore riskLevel attemptedAt"
            );

        const total = await LoginAttempt.countDocuments({ userId });

        return res.status(200).json({
            success: true,
            data: {
                attempts,
                pagination: {
                    total,
                    page,
                    pages: Math.ceil(total / limit),
                    limit,
                },
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Server error fetching biometric history.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// RESET MY BASELINE
// DELETE /api/biometrics/baseline/reset
// Protected
// ─────────────────────────────────────────
const resetBaseline = async (req, res) => {
    try {
        await User.findByIdAndUpdate(req.user.id, {
            behavioralBaseline: {
                avgTypingSpeed: null,
                avgDwellTime: null,
                avgFlightTime: null,
                sampleCount: 0,
            },
        });

        return res.status(200).json({
            success: true,
            message: "Behavioral baseline has been reset. It will rebuild over your next 3 logins.",
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Server error resetting baseline.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN — GET ANY USER'S BIOMETRIC HISTORY
// GET /api/biometrics/admin/:userId/history
// Admin only
// ─────────────────────────────────────────
const getUserBiometricHistory = async (req, res) => {
    try {
        const { userId } = req.params;
        const limit = parseInt(req.query.limit) || 20;
        const page = parseInt(req.query.page) || 1;
        const skip = (page - 1) * limit;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found." });
        }

        const attempts = await LoginAttempt.find({ userId })
            .sort({ attemptedAt: -1 })
            .skip(skip)
            .limit(limit);

        const total = await LoginAttempt.countDocuments({ userId });

        return res.status(200).json({
            success: true,
            data: {
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    behavioralBaseline: user.behavioralBaseline,
                },
                attempts,
                pagination: {
                    total,
                    page,
                    pages: Math.ceil(total / limit),
                    limit,
                },
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Server error fetching user biometric history.",
            error: error.message,
        });
    }
};

module.exports = {
    submitBiometrics,
    getMyBaseline,
    getBiometricHistory,
    resetBaseline,
    getUserBiometricHistory,
};