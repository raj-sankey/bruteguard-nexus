const express = require("express");
const dotenv = require("dotenv");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const connectDB = require("./config/db");

// ─────────────────────────────────────────
// LOAD ENV VARIABLES
// ─────────────────────────────────────────
dotenv.config();

// ─────────────────────────────────────────
// CONNECT TO MONGODB
// ─────────────────────────────────────────
connectDB();

// ─────────────────────────────────────────
// INIT EXPRESS APP
// ─────────────────────────────────────────
const app = express();

// ─────────────────────────────────────────
// GLOBAL MIDDLEWARES
// ─────────────────────────────────────────

// Security headers
app.use(helmet());

// CORS — allow React frontend later
app.use(cors({
    origin: process.env.CLIENT_URL || "http://localhost:3000",
    credentials: true,
}));

// Body parsers
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true }));

// HTTP request logger (only in development)
if (process.env.NODE_ENV === "development") {
    app.use(morgan("dev"));
}

// Global rate limiter — max 100 requests per 15 min per IP
const globalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: {
        success: false,
        message: "Too many requests from this IP. Please try again after 15 minutes.",
    },
    standardHeaders: true,
    legacyHeaders: false,
});
app.use(globalLimiter);

// ─────────────────────────────────────────
// HEALTH CHECK ROUTE
// ─────────────────────────────────────────
app.get("/api/health", (req, res) => {
    res.status(200).json({
        success: true,
        message: "BruteGuard Nexus API is running",
        environment: process.env.NODE_ENV,
        timestamp: new Date().toISOString(),
    });
});

// ─────────────────────────────────────────
// API ROUTES (will be added per phase)
// ─────────────────────────────────────────
app.use("/api/auth",       require("./routes/authRoutes"));
app.use("/api/biometrics", require("./routes/biometricRoutes"));
app.use("/api/context",    require("./routes/contextRoutes"));
app.use("/api/risk",       require("./routes/riskRoutes"));
app.use("/api/bruteforce",   require("./routes/bruteForceRoutes"));
app.use("/api/credstuffing", require("./routes/credentialStuffingRoutes"));
app.use("/api/mfa",          require("./routes/mfaRoutes"));
app.use("/api/trust",        require("./routes/trustScoreRoutes")); // Phase 9
app.use("/api/alerts",       require("./routes/alertRoutes"));      // Phase 10
app.use("/api/admin",        require("./routes/adminRoutes"));      // Phase 11
app.use("/api/analytics",    require("./routes/analyticsRoutes"));  // Phase 12

// ─────────────────────────────────────────
// 404 HANDLER — Unknown Routes
// ─────────────────────────────────────────
app.use((req, res, next) => {
    res.status(404).json({
        success: false,
        message: `Route ${req.originalUrl} not found`,
    });
});

// ─────────────────────────────────────────
// GLOBAL ERROR HANDLER
// ─────────────────────────────────────────
app.use((err, req, res, next) => {
    console.error("🔥 Error:", err.stack);

    const statusCode = err.statusCode || 500;
    const message = err.message || "Internal Server Error";

    res.status(statusCode).json({
        success: false,
        message,
        ...(process.env.NODE_ENV === "development" && { stack: err.stack }),
    });
});

// ─────────────────────────────────────────
// START SERVER
// ─────────────────────────────────────────
const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, () => {
    console.log(`🚀 Server running in ${process.env.NODE_ENV} mode on port ${PORT}`);
    console.log(`🔗 Health check: http://localhost:${PORT}/api/health`);
});

// ─────────────────────────────────────────
// HANDLE UNHANDLED PROMISE REJECTIONS
// ─────────────────────────────────────────
process.on("unhandledRejection", (err) => {
    console.error(`❌ Unhandled Rejection: ${err.message}`);
    server.close(() => process.exit(1));
});

// ─────────────────────────────────────────
// HANDLE UNCAUGHT EXCEPTIONS
// ─────────────────────────────────────────
process.on("uncaughtException", (err) => {
    console.error(`❌ Uncaught Exception: ${err.message}`);
    process.exit(1);
});