const SecurityAlert = require("../models/SecurityAlert");

// ─────────────────────────────────────────
// REUSABLE ALERT CREATOR
// Called from any module that needs to
// generate a security alert
// ─────────────────────────────────────────
const createAlert = async ({
    alertType,
    severity = "medium",
    userId = null,
    email = null,
    loginAttemptId = null,
    title,
    message,
    metadata = {},
    ipAddress = null,
    country = null,
    device = null,
    browser = null,
}) => {
    try {
        const alert = await SecurityAlert.create({
            alertType,
            severity,
            userId,
            email,
            loginAttemptId,
            title,
            message,
            metadata,
            ipAddress,
            country,
            device,
            browser,
            triggeredAt: new Date(),
        });

        console.log(`🚨 Alert Created [${severity.toUpperCase()}] — ${title}`);
        return alert;

    } catch (error) {
        console.error("❌ Failed to create security alert:", error.message);
        return null;
    }
};

// ─────────────────────────────────────────
// PRESET ALERT BUILDERS
// Convenience wrappers for common alerts
// ─────────────────────────────────────────

const createBruteForceAlert = async ({ userId, email, ipAddress, country, device, browser, attemptCount, loginAttemptId }) => {
    return createAlert({
        alertType: "brute_force",
        severity: "high",
        userId,
        email,
        loginAttemptId,
        title: "Brute Force Attack Detected",
        message: `Account ${email} has received ${attemptCount} consecutive failed login attempts. Account has been locked.`,
        metadata: { attemptCount },
        ipAddress,
        country,
        device,
        browser,
    });
};

const createAccountLockedAlert = async ({ userId, email, ipAddress, lockUntil }) => {
    return createAlert({
        alertType: "account_locked",
        severity: "high",
        userId,
        email,
        title: "Account Locked",
        message: `Account ${email} has been locked until ${new Date(lockUntil).toISOString()} due to too many failed login attempts.`,
        metadata: { lockUntil },
        ipAddress,
    });
};

const createHighRiskLoginAlert = async ({ userId, email, riskScore, riskFactors, ipAddress, country, device, browser, loginAttemptId }) => {
    return createAlert({
        alertType: "high_risk_login",
        severity: riskScore >= 85 ? "critical" : "high",
        userId,
        email,
        loginAttemptId,
        title: "High Risk Login Detected",
        message: `A high-risk login attempt (score: ${riskScore}) was detected for account ${email}.`,
        metadata: { riskScore, riskFactors },
        ipAddress,
        country,
        device,
        browser,
    });
};

const createNewDeviceAlert = async ({ userId, email, device, browser, os, ipAddress, country }) => {
    return createAlert({
        alertType: "new_device",
        severity: "low",
        userId,
        email,
        title: "Login from New Device",
        message: `Account ${email} logged in from a new device: ${device} (${browser}).`,
        metadata: { device, browser, os },
        ipAddress,
        country,
    });
};

const createNewCountryAlert = async ({ userId, email, country, ipAddress }) => {
    return createAlert({
        alertType: "new_country",
        severity: "medium",
        userId,
        email,
        title: "Login from New Country",
        message: `Account ${email} logged in from a new country: ${country}.`,
        metadata: { country },
        ipAddress,
        country,
    });
};

module.exports = {
    createAlert,
    createBruteForceAlert,
    createAccountLockedAlert,
    createHighRiskLoginAlert,
    createNewDeviceAlert,
    createNewCountryAlert,
};