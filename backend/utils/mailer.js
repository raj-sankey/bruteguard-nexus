const nodemailer = require("nodemailer");

// ─────────────────────────────────────────
// CREATE TRANSPORTER
// ─────────────────────────────────────────
const createTransporter = () => {
    return nodemailer.createTransport({
        host: process.env.MAIL_HOST || "smtp.gmail.com",
        port: parseInt(process.env.MAIL_PORT) || 587,
        secure: false, // TLS
        auth: {
            user: process.env.MAIL_USER,
            pass: process.env.MAIL_PASS,
        },
        tls: {
            rejectUnauthorized: false,
        },
    });
};

// ─────────────────────────────────────────
// SEND OTP EMAIL
// ─────────────────────────────────────────
const sendOTPEmail = async ({ to, name, otp, expirySeconds }) => {
    try {
        const transporter = createTransporter();
        const expiryMinutes = Math.ceil(expirySeconds / 60);

        const mailOptions = {
            from: process.env.MAIL_FROM || "BruteGuard Nexus <no-reply@bruteguard.com>",
            to,
            subject: "🔐 Your BruteGuard Nexus Verification Code",
            html: `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <style>
            body        { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 0; }
            .container  { max-width: 500px; margin: 40px auto; background: #ffffff; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            .header     { background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 30px; text-align: center; }
            .header h1  { color: #00d4ff; margin: 0; font-size: 22px; letter-spacing: 2px; }
            .header p   { color: #aaaaaa; margin: 5px 0 0; font-size: 13px; }
            .body       { padding: 30px; }
            .body p     { color: #444; font-size: 15px; line-height: 1.6; }
            .otp-box    { background: #f0f9ff; border: 2px dashed #00d4ff; border-radius: 10px; text-align: center; padding: 20px; margin: 25px 0; }
            .otp-code   { font-size: 42px; font-weight: bold; color: #1a1a2e; letter-spacing: 10px; margin: 0; }
            .otp-expiry { font-size: 13px; color: #888; margin-top: 8px; }
            .warning    { background: #fff8e1; border-left: 4px solid #ffc107; padding: 12px 16px; border-radius: 4px; margin-top: 20px; }
            .warning p  { color: #555; font-size: 13px; margin: 0; }
            .footer     { background: #f9f9f9; padding: 15px 30px; text-align: center; border-top: 1px solid #eee; }
            .footer p   { color: #aaa; font-size: 12px; margin: 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>🛡️ BRUTEGUARD NEXUS</h1>
              <p>Intelligent Adaptive Authentication</p>
            </div>
            <div class="body">
              <p>Hi <strong>${name}</strong>,</p>
              <p>We detected a login attempt that requires additional verification. Please use the code below to complete your login:</p>
              <div class="otp-box">
                <p class="otp-code">${otp}</p>
                <p class="otp-expiry">⏱ Expires in ${expiryMinutes} minute(s)</p>
              </div>
              <p>If you did not attempt to log in, please <strong>ignore this email</strong> and consider changing your password immediately.</p>
              <div class="warning">
                <p>⚠️ <strong>Never share this code</strong> with anyone. BruteGuard will never ask for your OTP via phone or chat.</p>
              </div>
            </div>
            <div class="footer">
              <p>© ${new Date().getFullYear()} BruteGuard Nexus — This is an automated message, please do not reply.</p>
            </div>
          </div>
        </body>
        </html>
      `,
        };

        const info = await transporter.sendMail(mailOptions);
        console.log(`✉️  OTP email sent to ${to} — MessageId: ${info.messageId}`);
        return { success: true, messageId: info.messageId };

    } catch (error) {
        console.error("❌ Email send error:", error.message);
        return { success: false, error: error.message };
    }
};

// ─────────────────────────────────────────
// SEND SECURITY ALERT EMAIL
// Generic security notification
// ─────────────────────────────────────────
const sendSecurityAlertEmail = async ({ to, name, subject, alertType, message, ipAddress, country, browser, time }) => {
    try {
        const transporter = createTransporter();

        const mailOptions = {
            from: process.env.MAIL_FROM || "BruteGuard Nexus <no-reply@bruteguard.com>",
            to,
            subject: subject || "⚠️ Security Alert — BruteGuard Nexus",
            html: `
        <!DOCTYPE html>
        <html>
        <head>
          <style>
            body       { font-family: Arial, sans-serif; background: #f4f4f4; margin: 0; padding: 0; }
            .container { max-width: 500px; margin: 40px auto; background: #fff; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 20px rgba(0,0,0,0.1); }
            .header    { background: linear-gradient(135deg, #c0392b, #e74c3c); padding: 25px; text-align: center; }
            .header h1 { color: #fff; margin: 0; font-size: 20px; }
            .body      { padding: 30px; }
            .body p    { color: #444; font-size: 15px; line-height: 1.6; }
            .info-box  { background: #fdf2f2; border: 1px solid #f5c6cb; border-radius: 8px; padding: 15px; margin: 20px 0; }
            .info-row  { display: flex; justify-content: space-between; margin-bottom: 8px; font-size: 14px; }
            .label     { color: #888; }
            .value     { color: #333; font-weight: bold; }
            .footer    { background: #f9f9f9; padding: 15px; text-align: center; border-top: 1px solid #eee; }
            .footer p  { color: #aaa; font-size: 12px; margin: 0; }
          </style>
        </head>
        <body>
          <div class="container">
            <div class="header">
              <h1>⚠️ Security Alert</h1>
            </div>
            <div class="body">
              <p>Hi <strong>${name}</strong>,</p>
              <p>${message}</p>
              <div class="info-box">
                <div class="info-row"><span class="label">Alert Type</span><span class="value">${alertType}</span></div>
                <div class="info-row"><span class="label">IP Address</span><span class="value">${ipAddress || "Unknown"}</span></div>
                <div class="info-row"><span class="label">Country</span><span class="value">${country || "Unknown"}</span></div>
                <div class="info-row"><span class="label">Browser</span><span class="value">${browser || "Unknown"}</span></div>
                <div class="info-row"><span class="label">Time</span><span class="value">${time || new Date().toISOString()}</span></div>
              </div>
              <p>If this was you, no action is needed. If not, please change your password immediately and contact support.</p>
            </div>
            <div class="footer">
              <p>© ${new Date().getFullYear()} BruteGuard Nexus</p>
            </div>
          </div>
        </body>
        </html>
      `,
        };

        const info = await transporter.sendMail(mailOptions);
        return { success: true, messageId: info.messageId };

    } catch (error) {
        console.error("❌ Security alert email error:", error.message);
        return { success: false, error: error.message };
    }
};

module.exports = { sendOTPEmail, sendSecurityAlertEmail };