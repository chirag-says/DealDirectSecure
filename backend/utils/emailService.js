import nodemailer from "nodemailer";

/**
 * Email Service for DealDirect
 * 
 * HOSTINGER CLOUD COMPATIBILITY:
 * - dotenv is NOT loaded here (handled centrally in server.js)
 * - All env vars come from process.env (injected by hPanel in production)
 * - NO fallback defaults for security-sensitive values
 */

// H7 FIX: Escape user-supplied values before interpolating into HTML templates
const escapeHtml = (str) => {
  if (str === null || str === undefined) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
};

// Create SMTP transporter
const createTransporter = () => {
  // SECURITY: No hardcoded fallbacks for sensitive values
  const smtpHost = process.env.SMTP_HOST;
  const smtpPort = process.env.SMTP_PORT;
  const smtpSecure = process.env.SMTP_SECURE === "true";
  const smtpUser = process.env.SMTP_USER || process.env.EMAIL_USER;
  const smtpPass = process.env.SMTP_PASS || process.env.EMAIL_PASS;

  // SMTP Configuration
  const smtpConfig = {
    host: smtpHost,
    port: smtpPort ? parseInt(smtpPort) : 587,
    secure: smtpSecure, // true for 465, false for other ports
    auth: {
      user: smtpUser,
      pass: smtpPass,
    },
  };

  // H8 FIX: Enable TLS verification by default to prevent MITM attacks.
  // Only disable via explicit SMTP_ALLOW_SELF_SIGNED=true for dev environments.
  if (!smtpConfig.secure) {
    smtpConfig.tls = {
      rejectUnauthorized: process.env.SMTP_ALLOW_SELF_SIGNED !== 'true'
    };
  }

  if (smtpHost && smtpUser) {
    console.log(`📧 SMTP configured: ${smtpHost}:${smtpConfig.port}`);
  } else {
    console.warn(`⚠️ SMTP not fully configured (host: ${smtpHost ? 'set' : 'missing'}, user: ${smtpUser ? 'set' : 'missing'})`);
  }

  return nodemailer.createTransport(smtpConfig);
};

// Email templates
const emailTemplates = {
  newLead: (ownerEmail, ownerName, leadData, propertyData) => ({
    subject: `🏠 New Lead for "${propertyData.title}"`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #2563eb, #1d4ed8); color: white; padding: 30px; border-radius: 12px 12px 0 0; text-align: center; }
          .header h1 { margin: 0; font-size: 24px; }
          .content { background: #f8fafc; padding: 30px; border: 1px solid #e2e8f0; }
          .property-card { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #e2e8f0; }
          .property-title { font-size: 18px; font-weight: 600; color: #1e40af; margin-bottom: 10px; }
          .property-details { color: #64748b; font-size: 14px; }
          .lead-card { background: white; padding: 20px; border-radius: 8px; border-left: 4px solid #10b981; }
          .lead-title { font-size: 16px; font-weight: 600; color: #059669; margin-bottom: 15px; }
          .lead-info { margin: 8px 0; }
          .lead-info strong { color: #374151; }
          .cta-button { display: inline-block; background: #2563eb; color: white; padding: 12px 30px; border-radius: 8px; text-decoration: none; font-weight: 600; margin-top: 20px; }
          .footer { text-align: center; padding: 20px; color: #64748b; font-size: 12px; }
          .icon { font-size: 20px; margin-right: 8px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>🎉 New Lead Alert!</h1>
            <p style="margin: 10px 0 0 0; opacity: 0.9;">Someone is interested in your property</p>
          </div>
          
          <div class="content">
            <p>Hi <strong>${escapeHtml(ownerName)}</strong>,</p>
            <p>Great news! A potential ${propertyData.listingType === 'Rent' ? 'tenant' : 'buyer'} has expressed interest in your property.</p>
            
            <div class="property-card">
              <div class="property-title">📍 ${propertyData.title}</div>
              <div class="property-details">
                <p>💰 ₹${propertyData.price?.toLocaleString('en-IN') || 'N/A'} ${propertyData.listingType === 'Rent' ? '/month' : ''}</p>
                <p>📌 ${propertyData.locality || ''}, ${propertyData.city || ''}</p>
                <p>🏷️ ${propertyData.propertyType || ''} ${propertyData.bhk ? `• ${propertyData.bhk}` : ''}</p>
              </div>
            </div>
            
            <div class="lead-card">
              <div class="lead-title">👤 Lead Details</div>
              <div class="lead-info"><strong>Name:</strong> ${escapeHtml(leadData.name)}</div>
              <div class="lead-info"><strong>Email:</strong> <a href="mailto:${encodeURIComponent(leadData.email)}">${escapeHtml(leadData.email)}</a></div>
              ${leadData.phone ? `<div class="lead-info"><strong>Phone:</strong> <a href="tel:${escapeHtml(leadData.phone)}">${escapeHtml(leadData.phone)}</a></div>` : ''}
              <div class="lead-info"><strong>Interested on:</strong> ${new Date().toLocaleDateString('en-IN', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}</div>
            </div>
            
            <p style="margin-top: 20px;">💡 <strong>Tip:</strong> Respond quickly to leads for better conversion rates. Properties with faster response times get 40% more conversions!</p>
            
            <center>
              <a href="https://dealdirect.in/my-properties?intendedFor=${encodeURIComponent(ownerEmail)}" class="cta-button">
                View All Leads →
              </a>
            </center>
          </div>
          
          <div class="footer">
            <p>This email was sent by Deal Direct</p>
            <p>© ${new Date().getFullYear()} Deal Direct. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `
      New Lead Alert!
      
      Hi ${ownerName},
      
      Someone is interested in your property: ${propertyData.title}
      
      Property Details:
      - Price: ₹${propertyData.price?.toLocaleString('en-IN') || 'N/A'}
      - Location: ${propertyData.locality || ''}, ${propertyData.city || ''}
      - Type: ${propertyData.propertyType || ''}
      
      Lead Details:
      - Name: ${leadData.name}
      - Email: ${leadData.email}
      - Phone: ${leadData.phone || 'Not provided'}
      
      View and manage this lead immediately here: https://dealdirect.in/my-properties?intendedFor=${encodeURIComponent(ownerEmail)}
      
      Best regards,
      Deal Direct Team
    `
  }),
  generalNotification: (userName, title, message, actionUrl = null, actionText = 'View Details') => ({
    subject: `🔔 Deal Direct: ${title}`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #2563eb, #1d4ed8); color: white; padding: 30px; border-radius: 12px 12px 0 0; text-align: center; }
          .header h1 { margin: 0; font-size: 24px; }
          .content { background: #f8fafc; padding: 30px; border: 1px solid #e2e8f0; }
          .message-box { background: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; border: 1px solid #e2e8f0; }
          .cta-button { display: inline-block; background: #2563eb; color: white; padding: 12px 30px; border-radius: 8px; text-decoration: none; font-weight: 600; margin-top: 20px; margin-bottom: 20px; }
          .footer { text-align: center; padding: 20px; color: #64748b; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>${title}</h1>
          </div>
          
          <div class="content">
            <p>Hi <strong>${escapeHtml(userName)}</strong>,</p>
            <div class="message-box">
              <p>${message}</p>
            </div>
            ${actionUrl ? `
            <center>
              <a href="${actionUrl}" class="cta-button">
                ${actionText} →
              </a>
            </center>
            ` : ''}
          </div>
          
          <div class="footer">
            <p>This email was sent by Deal Direct</p>
            <p>© ${new Date().getFullYear()} Deal Direct. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `
      ${title}
      
      Hi ${userName},
      
      ${message}
      ${actionUrl ? `\n      ${actionText}: ${actionUrl}` : ''}
      
      Best regards,
      Deal Direct Team
    `
  }),
  welcomeUser: (userName) => ({
    subject: `Welcome to the Revolution! 🏠 Your journey to a Broker-Free deal starts here.`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #e11d48, #be123c); color: white; padding: 30px; border-radius: 12px 12px 0 0; text-align: center; }
          .header h1 { margin: 0; font-size: 24px; }
          .content { background: #f8fafc; padding: 30px; border: 1px solid #e2e8f0; border-top: none; border-radius: 0 0 12px 12px; }
          .highlight-box { background: white; padding: 20px; border-radius: 8px; margin: 20px 0; border: 1px solid #e2e8f0; border-left: 4px solid #e11d48; }
          .reward-list { list-style: none; padding: 0; }
          .reward-list li { margin-bottom: 10px; padding-left: 20px; position: relative; }
          .reward-list li::before { content: '✓'; color: #e11d48; position: absolute; left: 0; font-weight: bold; }
          .cta-button { display: inline-block; background: #e11d48; color: white !important; padding: 12px 30px; border-radius: 8px; text-decoration: none; font-weight: 600; margin-top: 20px; text-align: center; }
          .footer { text-align: center; padding: 20px; color: #64748b; font-size: 12px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>Welcome to Deal Direct! 🏠</h1>
          </div>
          <div class="content">
            <p>Hi <strong>${userName}</strong>,</p>
            <p>Welcome to Deal Direct—the only property portal designed to put the power (and the savings) back in your hands.</p>
            <p>We built this platform with one goal: to eliminate middlemen and help you save lacs of rupees in unnecessary brokerage fees. Whether you are looking to buy, sell, or rent, you are now part of a community that values transparency and direct deals.</p>
            
            <div class="highlight-box">
              <h3 style="margin-top: 0; color: #e11d48;">🛡️ Our "Power of One" Rule</h3>
              <p style="margin-bottom: 0;">To keep our marketplace 100% spam-free and broker-free, we allow only <strong>1 active property post</strong> per user. This ensures that every listing you see is from a genuine owner or seeker—not a broker flooding the site with duplicates.</p>
            </div>

            <div class="highlight-box">
              <h3 style="margin-top: 0; color: #e11d48;">🎁 Earn While You Move</h3>
              <p>We don't just help you find a home; we reward you for it! Here's how you can start earning points today:</p>
              <ul class="reward-list">
                <li><strong>Post your Property:</strong> Get rewarded for sharing your space.</li>
                <li><strong>Make Enquiries:</strong> Earn points for being an active seeker.</li>
                <li><strong>Close the Deal:</strong> Tell us when you've successfully shaken hands on a deal for a milestone reward!</li>
                <li><strong>Refer a Friend:</strong> Share your unique link and earn when your friends join the community.</li>
              </ul>
            </div>

            <h3 style="color: #333;">🚀 What's Next?</h3>
            <ul class="reward-list">
              <li><strong>Complete Your Profile:</strong> Make sure your details are up to date.</li>
              <li><strong>Post Your Listing:</strong> Remember, make it count! Use high-quality photos.</li>
              <li><strong>Start Searching:</strong> Connect directly with owners and tenants today.</li>
            </ul>

            <center>
              <a href="https://dealdirect.in/properties" class="cta-button">Start Exploring Deal Direct</a>
            </center>

            <p style="margin-top: 30px; font-weight: bold; text-align: center;">Stop paying for introductions. Start dealing direct.</p>
            
            <p>Cheers,<br>The Deal Direct Team<br><a href="https://www.dealdirect.in" style="color: #e11d48;">www.dealdirect.in</a></p>
          </div>
          <div class="footer">
            <p>This email was sent by Deal Direct</p>
            <p>© ${new Date().getFullYear()} Deal Direct. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `
      Welcome to the Revolution! 🏠 Your journey to a Broker-Free deal starts here.
      
      Hi ${userName},
      
      Welcome to Deal Direct—the only property portal designed to put the power (and the savings) back in your hands.
      
      We built this platform with one goal: to eliminate middlemen and help you save lacs of rupees in unnecessary brokerage fees. Whether you are looking to buy, sell, or rent, you are now part of a community that values transparency and direct deals.
      
      🛡️ Our "Power of One" Rule
      To keep our marketplace 100% spam-free and broker-free, we allow only 1 active property post per user. This ensures that every listing you see is from a genuine owner or seeker—not a broker flooding the site with duplicates.
      
      🎁 Earn While You Move
      We don't just help you find a home; we reward you for it! Here's how you can start earning points today:
      - Post your Property: Get rewarded for sharing your space.
      - Make Enquiries: Earn points for being an active seeker.
      - Close the Deal: Tell us when you've successfully shaken hands on a deal for a milestone reward!
      - Refer a Friend: Share your unique link and earn when your friends join the community.
      
      🚀 What's Next?
      - Complete Your Profile: Make sure your details are up to date.
      - Post Your Listing: Remember, make it count! Use high-quality photos.
      - Start Searching: Connect directly with owners and tenants today.
      
      Stop paying for introductions. Start dealing direct.
      
      Cheers,
      The Deal Direct Team
      www.dealdirect.in
    `
  }),
  bookingAlert: (booking, projectName, unitName) => ({
    subject: `💰 New Booking Payment Submitted — ${unitName} at ${projectName}`,
    html: `
      <!DOCTYPE html>
      <html>
      <head>
        <style>
          body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; color: #333; margin: 0; padding: 0; }
          .container { max-width: 600px; margin: 0 auto; padding: 20px; }
          .header { background: linear-gradient(135deg, #4f46e5, #3730a3); color: white; padding: 28px 30px; border-radius: 12px 12px 0 0; }
          .header h1 { margin: 0 0 4px 0; font-size: 22px; }
          .header p { margin: 0; opacity: 0.85; font-size: 14px; }
          .content { background: #f8fafc; padding: 28px 30px; border: 1px solid #e2e8f0; }
          .card { background: white; padding: 20px; border-radius: 10px; margin-bottom: 16px; border: 1px solid #e2e8f0; }
          .card-title { font-size: 13px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em; color: #6366f1; margin-bottom: 12px; }
          .row { display: flex; justify-content: space-between; padding: 6px 0; border-bottom: 1px solid #f1f5f9; font-size: 14px; }
          .row:last-child { border-bottom: none; }
          .row .label { color: #64748b; }
          .row .value { font-weight: 600; color: #1e293b; text-align: right; }
          .utr-box { background: #fef9c3; border: 1px solid #fde68a; border-radius: 8px; padding: 14px; font-family: monospace; font-size: 18px; font-weight: 700; color: #92400e; text-align: center; margin: 16px 0; letter-spacing: 0.1em; }
          .cta-button { display: inline-block; background: #4f46e5; color: white !important; padding: 13px 32px; border-radius: 8px; text-decoration: none; font-weight: 700; font-size: 14px; }
          .footer { text-align: center; padding: 18px; color: #94a3b8; font-size: 12px; }
          .badge { display: inline-block; background: #dcfce7; color: #166534; padding: 3px 10px; border-radius: 20px; font-size: 12px; font-weight: 600; margin-left: 8px; }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="header">
            <h1>💰 Payment Proof Submitted</h1>
            <p>A client has submitted token payment for a unit booking — action required</p>
          </div>
          <div class="content">
            <div class="card">
              <div class="card-title">🏗️ Project & Unit</div>
              <div class="row"><span class="label">Project</span><span class="value">${projectName}</span></div>
              <div class="row"><span class="label">Unit Type</span><span class="value">${unitName}</span></div>
              <div class="row"><span class="label">Booking ID</span><span class="value" style="font-family:monospace">${booking._id?.toString()?.slice(-8)?.toUpperCase()}</span></div>
              <div class="row"><span class="label">Token Amount</span><span class="value">₹${booking.payment?.tokenAmount?.toLocaleString('en-IN') || '—'}</span></div>
            </div>
            <div class="card">
              <div class="card-title">👤 Client Details</div>
              <div class="row"><span class="label">Name</span><span class="value">${escapeHtml(booking.clientName)}</span></div>
              <div class="row"><span class="label">Phone</span><span class="value"><a href="tel:${escapeHtml(booking.clientPhone)}">${escapeHtml(booking.clientPhone)}</a></span></div>
              ${booking.clientEmail ? `<div class="row"><span class="label">Email</span><span class="value"><a href="mailto:${encodeURIComponent(booking.clientEmail)}">${escapeHtml(booking.clientEmail)}</a></span></div>` : ''}
              ${booking.notes ? `<div class="row"><span class="label">Notes</span><span class="value">${escapeHtml(booking.notes)}</span></div>` : ''}
            </div>
            <div class="card">
              <div class="card-title">🧩 Payment Proof</div>
              ${booking.payment?.utrNumber ? `
              <p style="margin: 0 0 8px; font-size: 13px; color: #64748b;">UTR / Transaction Reference:</p>
              <div class="utr-box">${booking.payment.utrNumber}</div>
              ` : '<p style="color:#64748b;font-size:14px;">No UTR provided — screenshot uploaded only.</p>'}
              ${booking.payment?.screenshotUrl ? `<p style="margin:0;font-size:14px;">📎 <a href="${booking.payment.screenshotUrl}" style="color:#4f46e5;font-weight:600;">View Payment Screenshot</a></p>` : ''}
            </div>
            <center style="margin-top: 8px;">
              <a href="${process.env.ADMIN_URL || 'http://localhost:5173'}/bookings" class="cta-button">Review Booking in Admin Panel →</a>
            </center>
            <p style="margin-top:20px;font-size:13px;color:#64748b;text-align:center;">Please verify and confirm or reject this booking within 24 hours.</p>
          </div>
          <div class="footer">
            <p>DealDirect Admin Notification · Auto-generated — do not reply</p>
            <p>© ${new Date().getFullYear()} DealDirect. All rights reserved.</p>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `
      New Booking Payment Submitted — Action Required

      Project: ${projectName}
      Unit: ${unitName}
      Booking ID: ${booking._id?.toString()?.slice(-8)?.toUpperCase()}
      Token Amount: ₹${booking.payment?.tokenAmount?.toLocaleString('en-IN') || '—'}

      Client: ${booking.clientName}
      Phone: ${booking.clientPhone}
      Email: ${booking.clientEmail || 'Not provided'}

      UTR / Reference: ${booking.payment?.utrNumber || 'Not provided'}
      Screenshot: ${booking.payment?.screenshotUrl || 'Not provided'}

      Review in Admin Panel: ${process.env.ADMIN_URL || 'http://localhost:5173'}/bookings
    `
  })
};

// Send email function
export const sendEmail = async (to, template, data) => {
  try {
    // Check if SMTP credentials are configured
    const smtpUser = process.env.SMTP_USER || process.env.EMAIL_USER;
    const smtpPass = process.env.SMTP_PASS || process.env.EMAIL_PASS;

    if (!smtpUser || !smtpPass) {
      console.log("⚠️ SMTP not configured. Skipping email notification.");
      console.log("📧 Would have sent email to:", to);
      return { success: true, skipped: true, message: "SMTP not configured" };
    }

    const transporter = createTransporter();

    // Verify SMTP connection
    await transporter.verify();
    console.log("✅ SMTP connection verified");

    const emailContent = emailTemplates[template](...data);

    const mailOptions = {
      from: `"Deal Direct" <${smtpUser}>`,
      to,
      subject: emailContent.subject,
      html: emailContent.html,
      text: emailContent.text
    };

    const info = await transporter.sendMail(mailOptions);
    console.log("✅ Email sent successfully:", info.messageId);

    return { success: true, messageId: info.messageId };
  } catch (error) {
    console.error("❌ Error sending email:", error.message);
    // Don't throw - email failure shouldn't break the main flow
    return { success: false, error: error.message };
  }
};

// Specific email functions
export const sendNewLeadNotification = async (ownerEmail, ownerName, leadData, propertyData) => {
  return sendEmail(ownerEmail, "newLead", [ownerEmail, ownerName, leadData, propertyData]);
};

export const sendGeneralNotification = async (userEmail, userName, title, message, actionUrl = null, actionText = null) => {
  return sendEmail(userEmail, "generalNotification", [userName, title, message, actionUrl, actionText]);
};

export const sendWelcomeEmail = async (userEmail, userName) => {
  return sendEmail(userEmail, "welcomeUser", [userName]);
};

// Send booking alert to admin when payment proof is submitted
export const sendBookingAlert = async (booking, projectName, unitName) => {
  const adminEmail = process.env.ADMIN_NOTIFY_EMAIL;
  if (!adminEmail) {
    console.warn('[BookingAlert] ADMIN_NOTIFY_EMAIL not set — skipping email notification.');
    return;
  }
  try {
    const smtpUser = process.env.SMTP_USER || process.env.EMAIL_USER;
    const smtpPass = process.env.SMTP_PASS || process.env.EMAIL_PASS;
    if (!smtpUser || !smtpPass) return;

    const transporter = createTransporter();
    const template = emailTemplates.bookingAlert(booking, projectName, unitName);
    await transporter.sendMail({
      from: `"DealDirect" <${smtpUser}>`,
      to: adminEmail,
      subject: template.subject,
      html: template.html,
      text: template.text,
    });
    console.log(`[BookingAlert] Admin notified at ${adminEmail} for booking ${booking._id}`);
  } catch (err) {
    console.error('[BookingAlert] Failed to send admin email:', err.message);
  }
};

export default {
  sendEmail,
  sendNewLeadNotification,
  sendGeneralNotification,
  sendWelcomeEmail,
  sendBookingAlert,
};
