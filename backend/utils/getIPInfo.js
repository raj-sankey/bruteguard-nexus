const geoip = require("geoip-lite");

/**
 * Get geolocation data from an IP address
 * Uses geoip-lite (offline — no API key needed)
 * @param {string} ip - IP address string
 * @returns {object}  - Location data
 */
const getIPInfo = (ip) => {
    try {
        // Handle localhost / private IPs
        if (
            !ip ||
            ip === "::1" ||
            ip === "127.0.0.1" ||
            ip.startsWith("192.168") ||
            ip.startsWith("10.") ||
            ip.startsWith("172.")
        ) {
            return {
                ip: ip || "127.0.0.1",
                country: "Local",
                region: "Local",
                city: "Local",
                ll: [0, 0],
                isp: "Local Network",
                isLocal: true,
            };
        }

        // Lookup IP in geoip-lite database
        const geo = geoip.lookup(ip);

        if (!geo) {
            return {
                ip,
                country: "Unknown",
                region: "Unknown",
                city: "Unknown",
                ll: [0, 0],
                isp: "Unknown",
                isLocal: false,
            };
        }

        return {
            ip,
            country: geo.country || "Unknown",
            region: geo.region || "Unknown",
            city: geo.city || "Unknown",
            ll: geo.ll || [0, 0],
            isp: geo.org || "Unknown",
            isLocal: false,
        };

    } catch (error) {
        console.error("❌ IP lookup error:", error.message);
        return {
            ip: ip || "unknown",
            country: "Unknown",
            region: "Unknown",
            city: "Unknown",
            ll: [0, 0],
            isp: "Unknown",
            isLocal: false,
        };
    }
};

/**
 * Extract real IP from request
 * Handles proxies, load balancers, and direct connections
 * @param {object} req - Express request object
 * @returns {string}   - IP address
 */
const extractIP = (req) => {
    const forwarded = req.headers["x-forwarded-for"];

    if (forwarded) {
        // x-forwarded-for can be a comma-separated list
        // First IP is the original client
        return forwarded.split(",")[0].trim();
    }

    return (
        req.headers["x-real-ip"] ||
        req.connection?.remoteAddress ||
        req.socket?.remoteAddress ||
        req.ip ||
        "unknown"
    );
};

module.exports = { getIPInfo, extractIP };