const User           = require("../models/User");
const TrustScoreLog  = require("../models/TrustScoreLog");
const { createAlert } = require("../utils/alertHelper");

// ─────────────────────────────────────────
// TRUST SCORE POINT SYSTEM
//
// All constants are defined here — never scattered across call-sites.
// A future env-based config can override these without touching service logic.
//
// Positive deltas (gains)
//   CLEAN_LOGIN_GAIN    — Successful, low-risk login (no MFA triggered)
//   MFA_SUCCESS_GAIN    — MFA was triggered AND the user passed it
//
// Negative deltas (penalties)
//   WRONG_PASSWORD_PENALTY       — One failed login attempt
//   HIGH_RISK_LOGIN_PENALTY      — Login with riskLevel === "high"
//   BRUTE_FORCE_PENALTY          — Account locked due to brute force
//   CREDENTIAL_STUFFING_PENALTY  — IP flagged for stuffing
//   ACCOUNT_LOCKED_PENALTY       — Account entered locked state
//   MFA_FAILED_PENALTY           — OTP expired or incorrect OTP submitted
// ─────────────────────────────────────────
const TRUST_POINTS = {
    // ── GAINS ────────────────────────────────
    CLEAN_LOGIN_GAIN:   3,   // Smooth, low-risk successful login
    MFA_SUCCESS_GAIN:   1,   // Passed MFA — positive but reduced (risk was still elevated)

    // ── PENALTIES ────────────────────────────
    WRONG_PASSWORD_PENALTY:       -5,   // Single failed password
    HIGH_RISK_LOGIN_PENALTY:      -10,  // riskLevel === "high"
    BRUTE_FORCE_PENALTY:          -15,  // Account locked by brute force
    CREDENTIAL_STUFFING_PENALTY:  -12,  // IP blocked for stuffing behaviour
    ACCOUNT_LOCKED_PENALTY:       -8,   // Separate lock event (not brute force path)
    MFA_FAILED_PENALTY:           -7,   // OTP failure
};

// ─────────────────────────────────────────
// TRUST LEVEL BANDS
// Classify a numeric score into a human-readable tier
// ─────────────────────────────────────────
const TRUST_BANDS = {
    EXCELLENT: { min: 80, max: 100, label: "excellent", description: "Account is highly trusted." },
    GOOD:      { min: 60, max: 79,  label: "good",      description: "Account in good standing." },
    FAIR:      { min: 40, max: 59,  label: "fair",      description: "Account has moderate risk activity." },
    POOR:      { min: 0,  max: 39,  label: "poor",      description: "Account shows significant risk signals." },
};

// Low-trust alert threshold — read from env, default 30
const TRUST_SCORE_LOW_THRESHOLD = parseInt(process.env.TRUST_SCORE_LOW_THRESHOLD) || 30;

// ─────────────────────────────────────────
// HELPER — Classify a numeric trust score
// ─────────────────────────────────────────
const getTrustLevel = (score) => {
    if (score >= TRUST_BANDS.EXCELLENT.min) return TRUST_BANDS.EXCELLENT;
    if (score >= TRUST_BANDS.GOOD.min)      return TRUST_BANDS.GOOD;
    if (score >= TRUST_BANDS.FAIR.min)      return TRUST_BANDS.FAIR;
    return TRUST_BANDS.POOR;
};

// ─────────────────────────────────────────
// HELPER — Clamp a value to [0, 100]
// ─────────────────────────────────────────
const clamp = (val) => Math.min(100, Math.max(0, val));

// ─────────────────────────────────────────
// INTERNAL — Persist delta and log it
//
// @param userId          — Mongoose ObjectId
// @param delta           — signed integer (positive = gain, negative = penalty)
// @param eventType       — matches TrustScoreLog eventType enum
// @param loginAttemptId  — optional, links the log entry to the LoginAttempt
// @param note            — human-readable description
// @param riskScoreAtEvent — risk score from riskService, if applicable
// ─────────────────────────────────────────
const applyTrustDelta = async ({
    userId,
    delta,
    eventType,
    loginAttemptId = null,
    note = null,
    riskScoreAtEvent = null,
}) => {
    // Fetch current score — use findByIdAndUpdate for atomic-ish update
    // We read first so we can compute scoreBefore/After for the log entry
    const user = await User.findById(userId).select("trustScore email name");
    if (!user) {
        console.warn(`⚠️  trustScoreService: user ${userId} not found — skipping delta`);
        return null;
    }

    const scoreBefore = user.trustScore;
    const scoreAfter  = clamp(scoreBefore + delta);

    // Persist updated score
    user.trustScore = scoreAfter;
    await user.save();

    // Append immutable audit log entry
    const logEntry = await TrustScoreLog.create({
        userId,
        eventType,
        delta,
        scoreBefore,
        scoreAfter,
        loginAttemptId,
        note,
        riskScoreAtEvent,
        loggedAt: new Date(),
    });

    console.log(
        `📊 Trust score [${user.email}]: ${scoreBefore} → ${scoreAfter} (${delta > 0 ? "+" : ""}${delta}) [${eventType}]`
    );

    // ─────────────────────────────────────────
    // FIRE LOW-TRUST ALERT
    // Only fires when the score crosses the threshold downward
    // (scoreBefore was above, scoreAfter is at or below)
    // ─────────────────────────────────────────
    if (scoreBefore > TRUST_SCORE_LOW_THRESHOLD && scoreAfter <= TRUST_SCORE_LOW_THRESHOLD) {
        await createAlert({
            alertType: "trust_score_drop",
            severity:  scoreAfter <= 15 ? "critical" : "high",
            userId,
            email:   user.email,
            title:   "Trust Score Dropped Below Threshold",
            message: `User ${user.email}'s trust score has fallen to ${scoreAfter} (threshold: ${TRUST_SCORE_LOW_THRESHOLD}). Event: ${eventType}.`,
            metadata: {
                scoreBefore,
                scoreAfter,
                threshold: TRUST_SCORE_LOW_THRESHOLD,
                eventType,
                delta,
            },
        });

        console.log(`🚨 Trust score drop alert fired for ${user.email} — score: ${scoreAfter}`);
    }

    return { scoreBefore, scoreAfter, delta, logEntry };
};

// ─────────────────────────────────────────
// updateTrustScoreOnLogin
//
// Master function called from authController and mfaService.
// Decides which delta to apply based on the login outcome.
//
// @param userId         — String or ObjectId
// @param options:
//   success             — Boolean: was the final authentication successful?
//   riskScore           — Number 0-100 from riskService
//   riskLevel           — "low" | "medium" | "high"
//   mfaTriggered        — Boolean: was MFA required?
//   mfaVerified         — Boolean: did the user pass MFA?
//   failureReason       — String: "wrong_password" | "account_locked" | "brute_force" |
//                                 "credential_stuffing" | "mfa_failed" | null
//   loginAttemptId      — ObjectId, for log linkage
// ─────────────────────────────────────────
const updateTrustScoreOnLogin = async (
    userId,
    {
        success          = false,
        riskScore        = 0,
        riskLevel        = "low",
        mfaTriggered     = false,
        mfaVerified      = false,
        failureReason    = null,
        loginAttemptId   = null,
    } = {}
) => {
    try {
        // ── FAILED AUTHENTICATION PATHS ───────────────────────────────

        // Brute force lock — harshest penalty
        if (failureReason === "brute_force") {
            return await applyTrustDelta({
                userId,
                delta:           TRUST_POINTS.BRUTE_FORCE_PENALTY,
                eventType:       "brute_force",
                loginAttemptId,
                note:            "Account locked after repeated failed login attempts.",
                riskScoreAtEvent: riskScore,
            });
        }

        // Credential stuffing IP block
        if (failureReason === "credential_stuffing") {
            return await applyTrustDelta({
                userId,
                delta:           TRUST_POINTS.CREDENTIAL_STUFFING_PENALTY,
                eventType:       "credential_stuffing",
                loginAttemptId,
                note:            "Login blocked — IP flagged for credential stuffing activity.",
                riskScoreAtEvent: riskScore,
            });
        }

        // Wrong password (single failed attempt, not yet locked)
        if (failureReason === "wrong_password" || (!success && !failureReason)) {
            return await applyTrustDelta({
                userId,
                delta:           TRUST_POINTS.WRONG_PASSWORD_PENALTY,
                eventType:       "wrong_password",
                loginAttemptId,
                note:            "Failed login — incorrect password.",
                riskScoreAtEvent: riskScore,
            });
        }

        // MFA failure (wrong or expired OTP)
        if (failureReason === "mfa_failed") {
            return await applyTrustDelta({
                userId,
                delta:           TRUST_POINTS.MFA_FAILED_PENALTY,
                eventType:       "mfa_failed",
                loginAttemptId,
                note:            "OTP verification failed or expired.",
                riskScoreAtEvent: riskScore,
            });
        }

        // Account locked (generic lock, e.g. from admin or another service)
        if (failureReason === "account_locked") {
            return await applyTrustDelta({
                userId,
                delta:           TRUST_POINTS.ACCOUNT_LOCKED_PENALTY,
                eventType:       "account_locked",
                loginAttemptId,
                note:            "Account is currently locked.",
                riskScoreAtEvent: riskScore,
            });
        }

        // ── SUCCESSFUL AUTHENTICATION PATHS ──────────────────────────

        if (success) {
            // High-risk successful login (MFA was required due to high risk, but passed)
            if (riskLevel === "high") {
                return await applyTrustDelta({
                    userId,
                    delta:           TRUST_POINTS.HIGH_RISK_LOGIN_PENALTY,
                    eventType:       "high_risk_login",
                    loginAttemptId,
                    note:            `High-risk login detected (score: ${riskScore}). Even though MFA passed, risk signals are significant.`,
                    riskScoreAtEvent: riskScore,
                });
            }

            // MFA was triggered and the user successfully passed it
            if (mfaTriggered && mfaVerified) {
                return await applyTrustDelta({
                    userId,
                    delta:           TRUST_POINTS.MFA_SUCCESS_GAIN,
                    eventType:       "mfa_success",
                    loginAttemptId,
                    note:            `MFA passed (risk score: ${riskScore}). Small positive adjustment.`,
                    riskScoreAtEvent: riskScore,
                });
            }

            // Clean, low-risk, no-MFA login — best outcome
            return await applyTrustDelta({
                userId,
                delta:           TRUST_POINTS.CLEAN_LOGIN_GAIN,
                eventType:       "clean_login",
                loginAttemptId,
                note:            `Successful low-risk login (score: ${riskScore}).`,
                riskScoreAtEvent: riskScore,
            });
        }

        // Fallback — unknown failure path, apply minimum penalty
        console.warn(`⚠️  trustScoreService: unhandled login outcome for user ${userId} — no delta applied`);
        return null;

    } catch (error) {
        // Trust score errors must NEVER crash the login flow
        console.error("❌ trustScoreService.updateTrustScoreOnLogin error:", error.message);
        return null;
    }
};

// ─────────────────────────────────────────
// getTrustScoreHistory
//
// Returns a paginated list of TrustScoreLog entries for a user.
// Each entry shows the event, delta, and before/after scores.
//
// @param userId   — String or ObjectId
// @param page     — 1-based page number (default 1)
// @param limit    — entries per page (default 20, max 100)
// ─────────────────────────────────────────
const getTrustScoreHistory = async (userId, { page = 1, limit = 20 } = {}) => {
    const safeLimit = Math.min(parseInt(limit) || 20, 100);
    const safePage  = Math.max(parseInt(page)  || 1, 1);
    const skip      = (safePage - 1) * safeLimit;

    const [logs, total] = await Promise.all([
        TrustScoreLog.find({ userId })
            .sort({ loggedAt: -1 })
            .skip(skip)
            .limit(safeLimit)
            .lean(),
        TrustScoreLog.countDocuments({ userId }),
    ]);

    return {
        logs,
        pagination: {
            page:       safePage,
            limit:      safeLimit,
            total,
            totalPages: Math.ceil(total / safeLimit),
        },
    };
};

// ─────────────────────────────────────────
// getRecentContributingEvents
//
// Returns the last N log entries + a summary for the "breakdown" section
// shown in the GET /api/trust/me endpoint.
// ─────────────────────────────────────────
const getRecentContributingEvents = async (userId, { limit = 10 } = {}) => {
    const logs = await TrustScoreLog.find({ userId })
        .sort({ loggedAt: -1 })
        .limit(limit)
        .lean();

    const totalGain  = logs.filter(l => l.delta > 0).reduce((s, l) => s + l.delta, 0);
    const totalLoss  = logs.filter(l => l.delta < 0).reduce((s, l) => s + l.delta, 0);

    return { recentEvents: logs, totalGain, totalLoss };
};

module.exports = {
    updateTrustScoreOnLogin,
    getTrustScoreHistory,
    getTrustLevel,
    getRecentContributingEvents,
    TRUST_POINTS,
    TRUST_BANDS,
    TRUST_SCORE_LOW_THRESHOLD,
};
