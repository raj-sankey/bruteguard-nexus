const jwt = require("jsonwebtoken");

/**
 * Generate a signed JWT token for a user
 * @param {string} userId - MongoDB _id of the user
 * @param {string} role   - User role (user | admin)
 * @returns {string}      - Signed JWT string
 */
const generateToken = (userId, role) => {
    return jwt.sign(
        {
            id: userId,
            role: role,
        },
        process.env.JWT_SECRET,
        {
            expiresIn: process.env.JWT_EXPIRES_IN || "7d",
        }
    );
};

module.exports = generateToken;