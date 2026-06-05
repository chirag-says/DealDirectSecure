import nodemailer from "nodemailer";

/**
 * Email Service for DealDirect
 * 
 * HOSTINGER CLOUD COMPATIBILITY:
 * - dotenv is NOT loaded here (handled centrally in server.js)
 * - All env vars come from process.env (injected by hPanel in production)
 * - NO fallback defaults for security-sensitive values
 */

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

  // Add TLS options for better compatibility
  if (!smtpConfig.secure) {
    smtpConfig.tls = {
      rejectUnauthorized: false // Allow self-signed certificates
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
            <p>Hi <strong>${ownerName}</strong>,</p>
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
              <div class="lead-info"><strong>Name:</strong> ${leadData.name}</div>
              <div class="lead-info"><strong>Email:</strong> <a href="mailto:${leadData.email}">${leadData.email}</a></div>
              ${leadData.phone ? `<div class="lead-info"><strong>Phone:</strong> <a href="tel:${leadData.phone}">${leadData.phone}</a></div>` : ''}
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
            <p>Hi <strong>${userName}</strong>,</p>
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

export default {
  sendEmail,
  sendNewLeadNotification,
  sendGeneralNotification,
  sendWelcomeEmail
};
