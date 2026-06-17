const User = require("../models/User");
const { getIPInfo, extractIP } = require("../utils/getIPInfo");
const { getDeviceInfo } = require("../utils/getDeviceInfo");

// ─────────────────────────────────────────
// COLLECT FULL CONTEXT FROM REQUEST
// Called on every login attempt
// ─────────────────────────────────────────
const collectContext = (req) => {
    // Extract IP
    const ip = extractIP(req);
    const ipInfo = getIPInfo(ip);

    // Extract device info from User-Agent
    const userAgent = req.headers["user-agent"] || null;
    const deviceInfo = getDeviceInfo(userAgent);

    return {
        ipAddress: ipInfo.ip,
        country: ipInfo.country,
        region: ipInfo.region,
        city: ipInfo.city,
        isp: ipInfo.isp,
        isLocal: ipInfo.isLocal,

        device: deviceInfo.device,
        browser: deviceInfo.browser,
        browserVersion: deviceInfo.browserVersion,
        os: deviceInfo.os,
        osVersion: deviceInfo.osVersion,
        deviceType: deviceInfo.deviceType,
        deviceVendor: deviceInfo.deviceVendor,
        userAgent: deviceInfo.userAgent,
        deviceFingerprint: deviceInfo.deviceFingerprint,
    };
};

// ─────────────────────────────────────────
// COMPARE CONTEXT AGAINST USER'S KNOWN DATA
// Returns flags for unknown IP, device, country
// ─────────────────────────────────────────
const compareContext = (context, user) => {
    const flags = {
        isKnownIP: false,
        isKnownDevice: false,
        isKnownCountry: false,
        isNewIP: false,
        isNewDevice: false,
        isNewCountry: false,
        riskFactors: [],
    };

    // Check IP
    if (user.knownIPs && user.knownIPs.includes(context.ipAddress)) {
        flags.isKnownIP = true;
    } else {
        flags.isNewIP = true;
        flags.riskFactors.push("Login from unrecognized IP address");
    }

    // Check device fingerprint
    if (
        context.deviceFingerprint &&
        user.knownDevices &&
        user.knownDevices.includes(context.deviceFingerprint)
    ) {
        flags.isKnownDevice = true;
    } else {
        flags.isNewDevice = true;
        flags.riskFactors.push("Login from unrecognized device or browser");
    }

    // Check country
    if (
        context.country &&
        user.knownCountries &&
        user.knownCountries.includes(context.country)
    ) {
        flags.isKnownCountry = true;
    } else {
        flags.isNewCountry = true;
        flags.riskFactors.push(`Login from new country: ${context.country}`);
    }

    return flags;
};

// ─────────────────────────────────────────
// UPDATE USER'S KNOWN CONTEXT AFTER
// SUCCESSFUL LOGIN
// ─────────────────────────────────────────
const updateKnownContext = async (userId, context) => {
    try {
        const user = await User.findById(userId);
        if (!user) return;

        let updated = false;

        // Add new IP (keep last 20 known IPs)
        if (context.ipAddress && !user.knownIPs.includes(context.ipAddress)) {
            user.knownIPs.push(context.ipAddress);
            if (user.knownIPs.length > 20) user.knownIPs.shift();
            updated = true;
        }

        // Add new device fingerprint (keep last 10)
        if (
            context.deviceFingerprint &&
            !user.knownDevices.includes(context.deviceFingerprint)
        ) {
            user.knownDevices.push(context.deviceFingerprint);
            if (user.knownDevices.length > 10) user.knownDevices.shift();
            updated = true;
        }

        // Add new country (keep last 10)
        if (
            context.country &&
            context.country !== "Unknown" &&
            !user.knownCountries.includes(context.country)
        ) {
            user.knownCountries.push(context.country);
            if (user.knownCountries.length > 10) user.knownCountries.shift();
            updated = true;
        }

        if (updated) await user.save();

    } catch (error) {
        console.error("❌ Error updating known context:", error.message);
    }
};

module.exports = {
    collectContext,
    compareContext,
    updateKnownContext,
};