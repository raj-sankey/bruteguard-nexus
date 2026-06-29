const User          = require("../models/User");
const generateToken = require("../utils/generateToken");
const LoginAttempt  = require("../models/LoginAttempt");
const {
    collectContext,
    compareContext,
    updateKnownContext,
} = require("../services/contextService");
const { evaluateLoginRisk } = require("../services/riskService");
const { handleFailedAttempt } = require("../services/bruteForceService");
const {
    createHighRiskLoginAlert,
    createNewDeviceAlert,
    createNewCountryAlert,
} = require("../utils/alertHelper");
const {
    isIPBlocked,
    detectCredentialStuffing,
} = require("../services/credentialStuffingService");
const { sendMFAOTP } = require("../services/mfaService");
const { updateTrustScoreOnLogin } = require("../services/trustScoreService"); // Phase 9


// ─────────────────────────────────────────
// REGISTER
// POST /api/auth/register
// ─────────────────────────────────────────
const register = async (req, res) => {
    try {
        const { name, email, password, role } = req.body;

        // Validate required fields
        if (!name || !email || !password) {
            return res.status(400).json({
                success: false,
                message: "Name, email, and password are required.",
            });
        }

        // Check if user already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({
                success: false,
                message: "An account with this email already exists.",
            });
        }

        // Password strength check
        if (password.length < 8) {
            return res.status(400).json({
                success: false,
                message: "Password must be at least 8 characters long.",
            });
        }

        // Create new user (password hashed via pre-save hook)
        const user = await User.create({
            name,
            email,
            password,
            role: role === "admin" ? "admin" : "user", // Prevent role injection
        });

        // Generate JWT
        const token = generateToken(user._id, user.role);

        return res.status(201).json({
            success: true,
            message: "Account created successfully.",
            token,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                trustScore: user.trustScore,
                riskScore: user.riskScore,
                createdAt: user.createdAt,
            },
        });

    } catch (error) {
        // Mongoose validation error
        if (error.name === "ValidationError") {
            const messages = Object.values(error.errors).map((e) => e.message);
            return res.status(400).json({
                success: false,
                message: messages.join(", "),
            });
        }

        return res.status(500).json({
            success: false,
            message: "Server error during registration.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// LOGIN
// POST /api/auth/login
// ─────────────────────────────────────────
const login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate fields
        if (!email || !password) {
            return res.status(400).json({
                success: false,
                message: "Email and password are required.",
            });
        }

        // Collect context early — needed for both failure and success paths
        const context = collectContext(req);

        // ─────────────────────────────────────────
        // STEP 2 — CHECK IF IP IS BLOCKED
        // ─────────────────────────────────────────
        const ipBlockStatus = await isIPBlocked(context.ipAddress);
        if (ipBlockStatus.blocked) {
            return res.status(403).json({
                success:     false,
                message:     ipBlockStatus.message,
                blocked:     true,
                blockUntil:  ipBlockStatus.blockUntil  || null,
                isPermanent: ipBlockStatus.isPermanent || false,
            });
        }

        // Find user — explicitly include password for comparison
        const user = await User.findOne({ email }).select("+password +otp +otpExpiresAt");

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password.",
            });
        }

        // Check if account is locked
        if (user.isAccountLocked()) {
            const remaining = Math.ceil((user.lockUntil - Date.now()) / 60000);
            return res.status(403).json({
                success: false,
                message: `Account is locked due to too many failed attempts. Try again in ${remaining} minute(s).`,
                lockUntil: user.lockUntil,
            });
        }

        // Auto-unlock if lock period expired
        if (user.isLocked && user.lockUntil < Date.now()) {
            await user.resetFailedAttempts();
        }

        // Compare password
        const isMatch = await user.comparePassword(password);

        if (!isMatch) {
            // Record failed attempt with context
            const failedAttempt = await LoginAttempt.create({
                userId:        user._id,
                email:         user.email,
                success:       false,
                failureReason: "wrong_password",
                context: {
                    ipAddress: context.ipAddress,
                    country:   context.country,
                    city:      context.city,
                    browser:   context.browser,
                    os:        context.os,
                    device:    context.device,
                    userAgent: context.userAgent,
                },
            });

            // Handle brute force detection
            const bruteForceResult = await handleFailedAttempt({
                userId:         user._id,
                email:          user.email,
                ipAddress:      context.ipAddress,
                country:        context.country,
                device:         context.device,
                browser:        context.browser,
                loginAttemptId: failedAttempt._id,
            });

            // ─────────────────────────────────────────
            // CREDENTIAL STUFFING DETECTION
            // ─────────────────────────────────────────
            await detectCredentialStuffing({
                ipAddress:      context.ipAddress,
                email:          user.email,
                country:        context.country,
                region:         context.region,
                city:           context.city,
                isp:            context.isp,
                loginAttemptId: failedAttempt._id,
                userId:         user._id,
            });

            if (bruteForceResult?.locked) {
                // ── Phase 9: Apply brute-force trust penalty ──────────
                await updateTrustScoreOnLogin(user._id, {
                    success:         false,
                    riskScore:       0,
                    riskLevel:       "high",
                    mfaTriggered:    false,
                    mfaVerified:     false,
                    failureReason:   "brute_force",
                    loginAttemptId:  failedAttempt._id,
                });

                return res.status(403).json({
                    success:      false,
                    message:      `Too many failed attempts. Account locked for ${process.env.ACCOUNT_LOCK_MINUTES || 30} minutes.`,
                    locked:       true,
                    lockUntil:    bruteForceResult.lockUntil,
                    attemptCount: bruteForceResult.attemptCount,
                });
            }

            // ── Phase 9: Apply wrong-password trust penalty ───────────
            // Note: this fires once per failed attempt (before brute-force lock).
            // On lock, the brute_force penalty fires instead (larger, no double-penalty).
            await updateTrustScoreOnLogin(user._id, {
                success:         false,
                riskScore:       0,
                riskLevel:       "low",
                mfaTriggered:    false,
                mfaVerified:     false,
                failureReason:   "wrong_password",
                loginAttemptId:  failedAttempt._id,
            });

            return res.status(401).json({
                success:      false,
                message:      `Invalid email or password. ${bruteForceResult?.attemptsLeft || 0} attempt(s) remaining before lockout.`,
                attemptsLeft: bruteForceResult?.attemptsLeft || 0,
            });
        }

        // ✅ Password matched — reset failed attempts
        await user.resetFailedAttempts();

        // ─────────────────────────────────────────
        // COMPARE CONTEXT AGAINST KNOWN USER DATA
        // ─────────────────────────────────────────
        const flags = compareContext(context, user);

        // Save LoginAttempt record with full context
        const loginAttempt = await LoginAttempt.create({
            userId:  user._id,
            email:   user.email,
            success: true,
            context: {
                ipAddress:         context.ipAddress,
                country:           context.country,
                city:              context.city,
                region:            context.region,
                isp:               context.isp,
                device:            context.device,
                browser:           context.browser,
                os:                context.os,
                userAgent:         context.userAgent,
                deviceFingerprint: context.deviceFingerprint,
                isKnownIP:         flags.isKnownIP,
                isKnownDevice:     flags.isKnownDevice,
                isKnownCountry:    flags.isKnownCountry,
            },
        });

        // Run CS detection even on success
        // (successful logins from stuffing IPs are still suspicious)
        await detectCredentialStuffing({
            ipAddress:      context.ipAddress,
            email:          user.email,
            country:        context.country,
            region:         context.region,
            city:           context.city,
            isp:            context.isp,
            loginAttemptId: loginAttempt._id,
            userId:         user._id,
        });

        // Update user last login info
        user.lastLoginAt = new Date();
        user.lastLoginIP = context.ipAddress;
        await user.save();

        // NOTE: updateKnownContext is intentionally deferred:
        //   ─ Low-risk path:  called below after token is generated
        //   ─ MFA path:       called inside verifyMFAOTP after OTP passes

        // ─────────────────────────────────────────
        // EVALUATE RISK SCORE
        // ─────────────────────────────────────────
        const riskResult = evaluateLoginRisk({
            user,
            contextFlags: flags,
            currentBiometrics: null, // Biometrics submitted separately after login
        });

        // Save risk data into the LoginAttempt record
        await LoginAttempt.findByIdAndUpdate(loginAttempt._id, {
            riskScore:   riskResult.score,
            riskLevel:   riskResult.level,
            riskFactors: riskResult.factors,
        });

        // Update user's current risk score
        await User.findByIdAndUpdate(user._id, {
            riskScore: riskResult.score,
        });

        // ─────────────────────────────────────────
        // ADAPTIVE MFA — Trigger based on risk level
        // ─────────────────────────────────────────
        const mediumThreshold = parseInt(process.env.RISK_MEDIUM_THRESHOLD) || 40;

        if (riskResult.score >= mediumThreshold) {
            // ── Phase 9: High-risk login penalty fires immediately ─────
            // MFA is required but NOT yet verified at this point.
            // If riskLevel is "high", we still penalise trust — the user
            // came in on highly suspicious signals even if they know the password.
            // For "medium" risk we do NOT penalise here; instead we wait:
            //   • mfaService.verifyMFAOTP fires MFA_SUCCESS_GAIN on pass
            //   • mfaService.verifyMFAOTP fires MFA_FAILED_PENALTY on fail
            // This avoids double-penalising a medium-risk user who legitimately
            // passes MFA (e.g. logging in from a new device for the first time).
            if (riskResult.level === "high") {
                await updateTrustScoreOnLogin(user._id, {
                    success:         true,   // Password was correct
                    riskScore:       riskResult.score,
                    riskLevel:       "high",
                    mfaTriggered:    true,
                    mfaVerified:     false,  // OTP not yet submitted
                    failureReason:   null,
                    loginAttemptId:  loginAttempt._id,
                });
            }

            // Send OTP email
            const otpResult = await sendMFAOTP({
                userId:         user._id,
                email:          user.email,
                name:           user.name,
                loginAttemptId: loginAttempt._id,
            });

            // Return MFA required response — NO token yet
            return res.status(200).json({
                success:        true,
                mfaRequired:    true,
                message:        "Login requires MFA verification. OTP sent to your email.",
                userId:         user._id,
                email:          user.email,
                loginAttemptId: loginAttempt._id,
                otpExpiresAt:   otpResult.expiresAt,
                risk: {
                    score:       riskResult.score,
                    level:       riskResult.level,
                    description: riskResult.description,
                    factors:     riskResult.factors,
                },
                // Dev only
                ...(process.env.NODE_ENV === "development" && { devOTP: otpResult.devOTP }),
            });
        }

        // ─────────────────────────────────────────
        // LOW RISK — Generate token and allow login
        // ─────────────────────────────────────────

        // Only register this context as trusted once we're sure
        // the user is being allowed straight through (no MFA needed)
        await updateKnownContext(user._id, context);

        const token = generateToken(user._id, user.role);

        // ── Phase 9: Clean login — apply positive trust delta ─────────
        // No MFA was triggered (risk was low), so this is the best-case path.
        await updateTrustScoreOnLogin(user._id, {
            success:         true,
            riskScore:       riskResult.score,
            riskLevel:       riskResult.level,
            mfaTriggered:    false,
            mfaVerified:     false,
            failureReason:   null,
            loginAttemptId:  loginAttempt._id,
        });

        // Trigger contextual alerts
        if (riskResult.score >= parseInt(process.env.RISK_HIGH_THRESHOLD || 70)) {
            await createHighRiskLoginAlert({
                userId:         user._id,
                email:          user.email,
                riskScore:      riskResult.score,
                riskFactors:    riskResult.factors,
                ipAddress:      context.ipAddress,
                country:        context.country,
                device:         context.device,
                browser:        context.browser,
                loginAttemptId: loginAttempt._id,
            });
        }

        if (flags.isNewDevice) {
            await createNewDeviceAlert({
                userId:    user._id,
                email:     user.email,
                device:    context.device,
                browser:   context.browser,
                os:        context.os,
                ipAddress: context.ipAddress,
                country:   context.country,
            });
        }

        if (flags.isNewCountry && !context.isLocal) {
            await createNewCountryAlert({
                userId:    user._id,
                email:     user.email,
                country:   context.country,
                ipAddress: context.ipAddress,
            });
        }

        return res.status(200).json({
            success:        true,
            mfaRequired:    false,
            message:        "Login successful.",
            token,
            loginAttemptId: loginAttempt._id,
            risk: {
                score:       riskResult.score,
                level:       riskResult.level,
                action:      riskResult.action,
                description: riskResult.description,
                factors:     riskResult.factors,
            },
            context: {
                ip:             context.ipAddress,
                country:        context.country,
                city:           context.city,
                browser:        context.browser,
                os:             context.os,
                device:         context.device,
                isKnownIP:      flags.isKnownIP,
                isKnownDevice:  flags.isKnownDevice,
                isKnownCountry: flags.isKnownCountry,
            },
            user: {
                id:          user._id,
                name:        user.name,
                email:       user.email,
                role:        user.role,
                trustScore:  user.trustScore,
                riskScore:   riskResult.score,
                lastLoginAt: user.lastLoginAt,
                lastLoginIP: user.lastLoginIP,
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Server error during login.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// GET PROFILE
// GET /api/auth/profile
// Protected route
// ─────────────────────────────────────────
const getProfile = async (req, res) => {
    try {
        const user = await User.findById(req.user.id);

        if (!user) {
            return res.status(404).json({
                success: false,
                message: "User not found.",
            });
        }

        return res.status(200).json({
            success: true,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role,
                trustScore: user.trustScore,
                riskScore: user.riskScore,
                isLocked: user.isLocked,
                failedLoginAttempts: user.failedLoginAttempts,
                behavioralBaseline: user.behavioralBaseline,
                knownIPs: user.knownIPs,
                knownDevices: user.knownDevices,
                knownCountries: user.knownCountries,
                lastLoginAt: user.lastLoginAt,
                lastLoginIP: user.lastLoginIP,
                createdAt: user.createdAt,
            },
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Server error fetching profile.",
            error: error.message,
        });
    }
};

// ─────────────────────────────────────────
// CHANGE PASSWORD
// PUT /api/auth/change-password
// Protected route
// ─────────────────────────────────────────
const changePassword = async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({
                success: false,
                message: "Current password and new password are required.",
            });
        }

        if (newPassword.length < 8) {
            return res.status(400).json({
                success: false,
                message: "New password must be at least 8 characters long.",
            });
        }

        // Fetch user with password
        const user = await User.findById(req.user.id).select("+password");

        const isMatch = await user.comparePassword(currentPassword);
        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: "Current password is incorrect.",
            });
        }

        user.password = newPassword; // Will be hashed by pre-save hook
        await user.save();

        return res.status(200).json({
            success: true,
            message: "Password changed successfully.",
        });

    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Server error changing password.",
            error: error.message,
        });
    }
};

module.exports = {
    register,
    login,
    getProfile,
    changePassword,
};