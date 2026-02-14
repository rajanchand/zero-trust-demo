/**
 * Email Sender Utility
 * ---
 * Sends OTP via Gmail SMTP using Nodemailer.
 * Falls back to console.log if email credentials are not configured.
 *
 * Required env vars:
 *   GMAIL_USER     – your Gmail address (e.g. rajanchand48@gmail.com)
 *   GMAIL_APP_PASS – Gmail App Password (NOT your regular password)
 */
const nodemailer = require('nodemailer');

let transporter = null;

// Create transporter only if credentials are set
if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASS) {
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_APP_PASS
    }
  });
  console.log('📧 Email transporter configured (Gmail)');
} else {
  console.log('📧 Email not configured – OTPs will be printed to console & shown in response');
}

/**
 * Send OTP via email.
 * @param {string} toEmail - Recipient email
 * @param {string} otp - The plain OTP code
 * @param {string} purpose - 'login' or 'step-up'
 * @returns {Promise<boolean>} true if email sent, false if fallback to console
 */
async function sendOTPEmail(toEmail, otp, purpose = 'login') {
  // Always log to console as backup
  console.log('');
  console.log('══════════════════════════════════════════');
  console.log(`  OTP for ${toEmail}: ${otp}`);
  console.log(`  Purpose: ${purpose} | Expires in 5 min`);
  console.log('══════════════════════════════════════════');
  console.log('');

  if (!transporter) {
    return false; // No email configured, fallback to console/response
  }

  try {
    const subject = purpose === 'step-up'
      ? '🔐 Zero Trust Demo – Step-Up Verification OTP'
      : '🔐 Zero Trust Demo – Login OTP';

    const html = `
      <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; padding: 20px;">
        <div style="background: #1a1a2e; color: #fff; padding: 20px; border-radius: 10px 10px 0 0; text-align: center;">
          <h2 style="margin: 0;">🛡️ Zero Trust Security Demo</h2>
          <p style="margin: 5px 0 0; opacity: 0.8;">MSc Dissertation – UWS</p>
        </div>
        <div style="background: #f8f9fa; padding: 30px; border-radius: 0 0 10px 10px;">
          <p>Hello,</p>
          <p>Your one-time password for <strong>${purpose}</strong> verification is:</p>
          <div style="background: #1a1a2e; color: #4ade80; font-size: 32px; font-weight: bold; text-align: center; padding: 20px; border-radius: 8px; letter-spacing: 8px; margin: 20px 0;">
            ${otp}
          </div>
          <p style="color: #666; font-size: 14px;">⏰ This OTP expires in <strong>5 minutes</strong>.</p>
          <p style="color: #666; font-size: 14px;">If you didn't request this, please ignore this email.</p>
          <hr style="border: none; border-top: 1px solid #ddd; margin: 20px 0;">
          <p style="color: #999; font-size: 12px; text-align: center;">Zero Trust Security Demo – University of the West of Scotland</p>
        </div>
      </div>
    `;

    await transporter.sendMail({
      from: `"Zero Trust Demo" <${process.env.GMAIL_USER}>`,
      to: toEmail,
      subject,
      html
    });

    console.log(`📧 OTP email sent to ${toEmail}`);
    return true; // Email sent successfully
  } catch (err) {
    console.error(`📧 Failed to send email to ${toEmail}:`, err.message);
    return false; // Fallback to console/response
  }
}

module.exports = { sendOTPEmail };
