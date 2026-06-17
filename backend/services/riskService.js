const { compareBiometricsToBaseline } = require("./biometricService");

// ─────────────────────────────────────────
// RISK WEIGHTS
// How much each factor contributes to
// the final risk score (must sum to 100)
// ─────────────────────────────────────────
const RISK_WEIGHTS = {
    newIP: 20, // Login from unrecognized IP
    newDevice: 20, // Login from unrecognized device
    newCountry: 25, // Login from new country
    biometricDeviation: 20, // Typing pattern mismatch
    failedAttempts: 15, // Recent failed login history
};

// ─────────────────────────────────────────
// RISK THRESHOLDS
// ─────────────────────────────────────────
const RISK_LEVELS = {
    LOW: { max: 39, label: "low", action: "allow" },
    MEDIUM: { max: 69, label: "medium", action: "trigger_mfa" },
    HIGH: { max: 100, label: "high", action: "block_or_mfa" },
};

// ─────────────────────────────────────────
// CLASSIFY RISK SCORE INTO LEVEL
// ─────────────────────────────────────────
const classifyRisk = (score) => {
    if (score <= RISK_LEVELS.LOW.max) {
        return {
            level: "low",
            action: "allow",
            description: "Login appears normal. Access granted.",
        };
    } else if (score <= RISK_LEVELS.MEDIUM.max) {
        return {
            level: "medium",
            action: "trigger_mfa",
            description: "Unusual activity detected. MFA required.",
        };
    } else {
        return {
            level: "high",
            action: "block_or_mfa",
            description: "High risk detected. Access blocked or MFA required.",
        };
    }
};

// ─────────────────────────────────────────
// CORE RISK CALCULATION ENGINE
// Takes all context + biometric data
// Returns score 0–100 + breakdown
// ─────────────────────────────────────────
const calculateRiskScore = ({
    contextFlags,
    biometricDeviation,
    failedAttempts,
    user,
}) => {
    let score = 0;
    const factors = [];
    const breakdown = {};

    // ── 1. NEW IP ──────────────────────────
    if (contextFlags?.isNewIP) {
        const contribution = RISK_WEIGHTS.newIP;
        score += contribution;
        breakdown.newIP = contribution;
        factors.push("Login from unrecognized IP address");
    } else {
        breakdown.newIP = 0;
    }

    // ── 2. NEW DEVICE ──────────────────────
    if (contextFlags?.isNewDevice) {
        const contribution = RISK_WEIGHTS.newDevice;
        score += contribution;
        breakdown.newDevice = contribution;
        factors.push("Login from unrecognized device or browser");
    } else {
        breakdown.newDevice = 0;
    }

    // ── 3. NEW COUNTRY ─────────────────────
    if (contextFlags?.isNewCountry) {
        const contribution = RISK_WEIGHTS.newCountry;
        score += contribution;
        breakdown.newCountry = contribution;
        factors.push(`Login from new country: ${contextFlags.country || "Unknown"}`);
    } else {
        breakdown.newCountry = 0;
    }

    // ── 4. BIOMETRIC DEVIATION ─────────────
    // deviationScore is 0–100
    // We scale it to our weight (max 20 pts)
    if (biometricDeviation !== null && biometricDeviation !== undefined) {
        const contribution = parseFloat(
            ((biometricDeviation / 100) * RISK_WEIGHTS.biometricDeviation).toFixed(2)
        );
        score += contribution;
        breakdown.biometricDeviation = contribution;

        if (biometricDeviation > 50) {
            factors.push(
                `Typing pattern deviation: ${biometricDeviation.toFixed(1)}% from baseline`
            );
        }
    } else {
        breakdown.biometricDeviation = 0;
    }

    // ── 5. FAILED ATTEMPTS ─────────────────
    // Scale: 1 attempt = 3pts, 2 = 6pts, 3 = 9pts, 4 = 12pts, 5+ = 15pts
    if (failedAttempts && failedAttempts > 0) {
        const contribution = Math.min(
            RISK_WEIGHTS.failedAttempts,
            failedAttempts * 3
        );
        score += contribution;
        breakdown.failedAttempts = contribution;
        factors.push(`${failedAttempts} recent failed login attempt(s)`);
    } else {
        breakdown.failedAttempts = 0;
    }

    // ── BONUS RISK: IMPOSSIBLE TRAVEL ──────
    // If user logged in from country A recently
    // and now logging in from country B — flag it
    if (
        user?.lastLoginAt &&
        contextFlags?.isNewCountry &&
        !contextFlags?.isLocal
    ) {
        const hoursSinceLastLogin =
            (Date.now() - new Date(user.lastLoginAt).getTime()) / (1000 * 60 * 60);

        if (hoursSinceLastLogin < 2) {
            score += 10;
            breakdown.impossibleTravel = 10;
            factors.push(
                `Possible impossible travel — country changed within ${hoursSinceLastLogin.toFixed(1)} hour(s)`
            );
        }
    }

    // ── CAP SCORE AT 100 ───────────────────
    score = Math.min(100, parseFloat(score.toFixed(2)));

    // ── CLASSIFY ───────────────────────────
    const classification = classifyRisk(score);

    return {
        score,
        level: classification.level,
        action: classification.action,
        description: classification.description,
        factors,
        breakdown,
    };
};

// ─────────────────────────────────────────
// EVALUATE FULL LOGIN RISK
// Master function called during login
// Ties together context + biometrics
// ─────────────────────────────────────────
const evaluateLoginRisk = ({
    user,
    contextFlags,
    currentBiometrics,
}) => {
    // Compare biometrics to baseline
    const { deviationScore } = compareBiometricsToBaseline(
        currentBiometrics || {},
        user.behavioralBaseline
    );

    // Get failed attempts from user record
    const failedAttempts = user.failedLoginAttempts || 0;

    // Calculate final risk score
    const result = calculateRiskScore({
        contextFlags,
        biometricDeviation: deviationScore,
        failedAttempts,
        user,
    });

    return {
        ...result,
        deviationScore,
        meta: {
            baselineSampleCount: user.behavioralBaseline?.sampleCount || 0,
            biometricsUsed: (user.behavioralBaseline?.sampleCount || 0) >= 3,
            contextChecked: true,
        },
    };
};

module.exports = {
    calculateRiskScore,
    evaluateLoginRisk,
    classifyRisk,
    RISK_WEIGHTS,
    RISK_LEVELS,
};