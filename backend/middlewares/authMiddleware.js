const jwt = require("jsonwebtoken");
const User = require("../models/User");

// ─────────────────────────────────────────
// PROTECT — Verify JWT and attach user to req
// ─────────────────────────────────────────
const protect = async (req, res, next) => {
    try {
        let token;

        // Check Authorization header
        if (
            req.headers.authorization &&
            req.headers.authorization.startsWith("Bearer ")
        ) {
            token = req.headers.authorization.split(" ")[1];
        }

        if (!token) {
            return res.status(401).json({
                success: false,
                message: "Access denied. No token provided.",
            });
        }

        // Verify token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Attach user to request (excluding password)
        const user = await User.findById(decoded.id).select("-password");

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Token is valid but user no longer exists.",
            });
        }

        // Check if account is locked
        if (user.isAccountLocked()) {
            return res.status(403).json({
                success: false,
                message: "Your account is temporarily locked. Please try again later.",
                lockUntil: user.lockUntil,
            });
        }

        req.user = user;
        next();

    } catch (error) {
        if (error.name === "JsonWebTokenError") {
            return res.status(401).json({
                success: false,
                message: "Invalid token. Please log in again.",
            });
        }

        if (error.name === "TokenExpiredError") {
            return res.status(401).json({
                success: false,
                message: "Token has expired. Please log in again.",
            });
        }

        return res.status(500).json({
            success: false,
            message: "Authentication error.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// ADMIN ONLY — Must come after protect
// ─────────────────────────────────────────
const adminOnly = (req, res, next) => {
    if (req.user && req.user.role === "admin") {
        return next();
    }

    return res.status(403).json({
        success: false,
        message: "Access denied. Admins only.",
    });
};

module.exports = { protect, adminOnly };