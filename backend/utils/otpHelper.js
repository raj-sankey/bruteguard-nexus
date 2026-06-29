const crypto = require("crypto");
const bcrypt = require("bcryptjs");

// ─────────────────────────────────────────
// GENERATE A 6-DIGIT OTP
// Uses crypto for true randomness
// ─────────────────────────────────────────
const generateOTP = () => {
    // Generate random number between 100000 and 999999
    const otp = crypto.randomInt(100000, 999999).toString();
    return otp;
};

// ─────────────────────────────────────────
// HASH OTP BEFORE STORING IN DB
// Never store raw OTP in database
// ─────────────────────────────────────────
const hashOTP = async (otp) => {
    const salt = await bcrypt.genSalt(10);
    const hashed = await bcrypt.hash(otp, salt);
    return hashed;
};

// ─────────────────────────────────────────
// VERIFY OTP AGAINST HASH
// ─────────────────────────────────────────
const verifyOTP = async (inputOTP, hashedOTP) => {
    return await bcrypt.compare(inputOTP, hashedOTP);
};

// ─────────────────────────────────────────
// CHECK IF OTP IS EXPIRED
// ─────────────────────────────────────────
const isOTPExpired = (otpExpiresAt) => {
    if (!otpExpiresAt) return true;
    return new Date(otpExpiresAt) < new Date();
};

// ─────────────────────────────────────────
// GET OTP EXPIRY DATE
// ─────────────────────────────────────────
const getOTPExpiry = () => {
    const seconds = parseInt(process.env.OTP_EXPIRY_SECONDS) || 300; // 5 minutes default
    return new Date(Date.now() + seconds * 1000);
};

module.exports = {
    generateOTP,
    hashOTP,
    verifyOTP,
    isOTPExpired,
    getOTPExpiry,
};