const User = require("../models/User");

// ─────────────────────────────────────────
// CALCULATE BIOMETRIC AVERAGES FROM RAW DATA
// ─────────────────────────────────────────
const calculateBiometricAverages = (keystrokes) => {
    if (!keystrokes || keystrokes.length === 0) {
        return {
            typingSpeed: null,
            avgDwellTime: null,
            avgFlightTime: null,
            keystrokeCount: 0,
        };
    }

    // Filter valid entries
    const validDwells = keystrokes.filter((k) => k.dwellTime > 0).map((k) => k.dwellTime);
    const validFlights = keystrokes.filter((k) => k.flightTime > 0).map((k) => k.flightTime);

    const avgDwellTime = validDwells.length > 0
        ? parseFloat((validDwells.reduce((a, b) => a + b, 0) / validDwells.length).toFixed(2))
        : null;

    const avgFlightTime = validFlights.length > 0
        ? parseFloat((validFlights.reduce((a, b) => a + b, 0) / validFlights.length).toFixed(2))
        : null;

    // Typing speed = total time from first to last keystroke (ms)
    const timestamps = keystrokes.map((k) => k.timestamp).filter(Boolean);
    const typingSpeed = timestamps.length >= 2
        ? parseFloat((timestamps[timestamps.length - 1] - timestamps[0]).toFixed(2))
        : null;

    return {
        typingSpeed,
        avgDwellTime,
        avgFlightTime,
        keystrokeCount: keystrokes.length,
    };
};

// ─────────────────────────────────────────
// UPDATE USER BEHAVIORAL BASELINE
// Uses rolling average — blends new data
// into existing baseline smoothly
// ─────────────────────────────────────────
const updateBehavioralBaseline = async (userId, newBiometrics) => {
    try {
        const user = await User.findById(userId);
        if (!user) return null;

        const baseline = user.behavioralBaseline;
        const sampleCount = baseline.sampleCount || 0;

        // Need at least valid values to update
        const { typingSpeed, avgDwellTime, avgFlightTime } = newBiometrics;

        // Rolling average formula: newAvg = (oldAvg * n + newValue) / (n + 1)
        const rollingAvg = (oldAvg, newVal, n) => {
            if (newVal === null || newVal === undefined) return oldAvg;
            if (oldAvg === null) return newVal;
            return parseFloat(((oldAvg * n + newVal) / (n + 1)).toFixed(2));
        };

        user.behavioralBaseline = {
            avgTypingSpeed: rollingAvg(baseline.avgTypingSpeed, typingSpeed, sampleCount),
            avgDwellTime: rollingAvg(baseline.avgDwellTime, avgDwellTime, sampleCount),
            avgFlightTime: rollingAvg(baseline.avgFlightTime, avgFlightTime, sampleCount),
            sampleCount: sampleCount + 1,
        };

        await user.save();
        return user.behavioralBaseline;

    } catch (error) {
        console.error("❌ Error updating behavioral baseline:", error.message);
        return null;
    }
};

// ─────────────────────────────────────────
// COMPARE CURRENT BIOMETRICS VS BASELINE
// Returns deviation score 0–100
// Higher = more deviation = more suspicious
// ─────────────────────────────────────────
const compareBiometricsToBaseline = (current, baseline) => {
    // Not enough baseline data yet
    if (!baseline || baseline.sampleCount < 3) {
        return {
            deviationScore: 0,
            details: { message: "Insufficient baseline data — skipping biometric comparison" },
        };
    }

    const deviations = [];
    const details = {};

    // Helper — percentage deviation between two values
    const percentDeviation = (current, baseline) => {
        if (!current || !baseline) return 0;
        return Math.abs((current - baseline) / baseline) * 100;
    };

    // Typing speed deviation
    if (current.typingSpeed && baseline.avgTypingSpeed) {
        const dev = percentDeviation(current.typingSpeed, baseline.avgTypingSpeed);
        deviations.push(dev);
        details.typingSpeedDeviation = parseFloat(dev.toFixed(2));
    }

    // Dwell time deviation
    if (current.avgDwellTime && baseline.avgDwellTime) {
        const dev = percentDeviation(current.avgDwellTime, baseline.avgDwellTime);
        deviations.push(dev);
        details.dwellTimeDeviation = parseFloat(dev.toFixed(2));
    }

    // Flight time deviation
    if (current.avgFlightTime && baseline.avgFlightTime) {
        const dev = percentDeviation(current.avgFlightTime, baseline.avgFlightTime);
        deviations.push(dev);
        details.flightTimeDeviation = parseFloat(dev.toFixed(2));
    }

    if (deviations.length === 0) {
        return { deviationScore: 0, details: { message: "No biometric data to compare" } };
    }

    // Average deviation across all metrics
    const avgDeviation = deviations.reduce((a, b) => a + b, 0) / deviations.length;

    // Normalize to 0–100 scale
    // >100% deviation = max score of 100
    const deviationScore = Math.min(100, parseFloat(avgDeviation.toFixed(2)));

    return { deviationScore, details };
};

module.exports = {
    calculateBiometricAverages,
    updateBehavioralBaseline,
    compareBiometricsToBaseline,
};