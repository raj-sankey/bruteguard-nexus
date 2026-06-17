const UAParser = require("ua-parser-js");
const crypto = require("crypto");

/**
 * Parse User-Agent string into structured device info
 * @param {string} userAgent - Raw User-Agent header
 * @returns {object}         - Parsed device + browser + OS info
 */
const getDeviceInfo = (userAgent) => {
    try {
        if (!userAgent) {
            return {
                browser: "Unknown",
                browserVersion: "Unknown",
                os: "Unknown",
                osVersion: "Unknown",
                device: "Unknown",
                deviceType: "Unknown",
                deviceVendor: "Unknown",
                userAgent: null,
                deviceFingerprint: null,
            };
        }

        const parser = new UAParser(userAgent);
        const result = parser.getResult();

        // Extract fields safely
        const browser = result.browser?.name || "Unknown";
        const browserVersion = result.browser?.version || "Unknown";
        const os = result.os?.name || "Unknown";
        const osVersion = result.os?.version || "Unknown";
        const deviceVendor = result.device?.vendor || "Unknown";
        const deviceModel = result.device?.model || "Unknown";
        const deviceType = result.device?.type || "desktop"; // mobile, tablet, desktop

        // Human-readable device string
        const device =
            deviceVendor !== "Unknown" && deviceModel !== "Unknown"
                ? `${deviceVendor} ${deviceModel}`
                : `${os} ${deviceType}`;

        // Generate a fingerprint hash from stable device properties
        // This stays the same for the same browser/OS/device combo
        const fingerprintSource = `${browser}-${browserVersion.split(".")[0]}-${os}-${osVersion}-${deviceType}-${deviceVendor}`;
        const deviceFingerprint = crypto
            .createHash("sha256")
            .update(fingerprintSource)
            .digest("hex")
            .substring(0, 32); // 32 char fingerprint

        return {
            browser,
            browserVersion,
            os,
            osVersion,
            device,
            deviceType,
            deviceVendor,
            userAgent,
            deviceFingerprint,
        };

    } catch (error) {
        console.error("❌ Device parsing error:", error.message);
        return {
            browser: "Unknown",
            browserVersion: "Unknown",
            os: "Unknown",
            osVersion: "Unknown",
            device: "Unknown",
            deviceType: "Unknown",
            deviceVendor: "Unknown",
            userAgent: userAgent || null,
            deviceFingerprint: null,
        };
    }
};

module.exports = { getDeviceInfo };