/**
 * One-time script: Retroactively sync confirmed/completed bookings to Group Buy campaigns.
 * 
 * For each confirmed/completed booking that has a user AND a matching active campaign,
 * creates a CampaignMember record (if not already present) with tokenStatus: "paid".
 * 
 * Run: node scripts/sync-bookings-to-campaigns.js
 */
import mongoose from "mongoose";
import dotenv from "dotenv";
dotenv.config();

import ProjectBooking from "../models/ProjectBooking.js";
import GroupBuyCampaign from "../models/GroupBuyCampaign.js";
import CampaignMember from "../models/CampaignMember.js";
import User from "../models/userModel.js";

const MONGO_URI = process.env.MONGO_URI || process.env.MONGODB_URI;

async function run() {
  await mongoose.connect(MONGO_URI);
  console.log("Connected to MongoDB");

  // Find all confirmed/completed bookings with a user reference
  const bookings = await ProjectBooking.find({
    status: { $in: ["confirmed", "completed"] },
    user: { $ne: null },
  }).lean();

  console.log(`Found ${bookings.length} confirmed/completed bookings with user refs`);

  let synced = 0;
  let skipped = 0;

  for (const booking of bookings) {
    // Find active campaign for this project+unitType
    const campaign = await GroupBuyCampaign.findOne({
      project: booking.project,
      unitType: booking.unitType,
      status: "active",
    });

    if (!campaign) {
      console.log(`  [SKIP] No active campaign for project=${booking.project} unitType=${booking.unitType}`);
      skipped++;
      continue;
    }

    // Check if already enrolled
    const existing = await CampaignMember.findOne({
      campaign: campaign._id,
      user: booking.user,
    });

    if (existing) {
      if (existing.tokenStatus !== "paid") {
        existing.tokenStatus = "paid";
        existing.tokenPaidAt = new Date();
        existing.paymentReference = booking.payment?.utrNumber || existing.paymentReference;
        await existing.save();
        console.log(`  [UPDATED] User ${booking.user} marked as paid in campaign ${campaign._id}`);
        synced++;
      } else {
        console.log(`  [SKIP] User ${booking.user} already a paid member of campaign ${campaign._id}`);
        skipped++;
      }
      continue;
    }

    // Get user snapshot
    const user = await User.findById(booking.user).select("name email phone").lean();

    // Create new paid member
    try {
      await CampaignMember.create({
        campaign: campaign._id,
        user: booking.user,
        status: "active",
        tokenStatus: "paid",
        tokenPaidAt: new Date(),
        paymentReference: booking.payment?.utrNumber || "",
        userSnapshot: {
          name: user?.name || booking.clientName,
          email: user?.email || booking.clientEmail,
          phone: user?.phone || booking.clientPhone,
        },
      });
      console.log(`  [SYNCED] User ${booking.user} → campaign ${campaign._id} (booking ${booking._id})`);
      synced++;
    } catch (err) {
      if (err.code === 11000) {
        console.log(`  [SKIP] Duplicate key for user ${booking.user} in campaign ${campaign._id}`);
        skipped++;
      } else {
        console.error(`  [ERROR] ${err.message}`);
      }
    }
  }

  console.log(`\nDone. Synced: ${synced}, Skipped: ${skipped}`);
  await mongoose.disconnect();
}

run().catch(err => {
  console.error("Fatal error:", err);
  process.exit(1);
});
