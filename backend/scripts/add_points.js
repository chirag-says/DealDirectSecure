/**
 * One-off script: Add 1,000,000 points to a user's reward wallet.
 *
 * Usage:  node scripts/add_points.js
 *
 * This bypasses the MAX_ADMIN_ADJUSTMENT_POINTS cap that guards the HTTP route,
 * because this is an intentional, operator-level adjustment run locally.
 */
import 'dotenv/config';
import mongoose from 'mongoose';
import User from '../models/userModel.js';
import Reward from '../models/Reward.js';

const TARGET_EMAIL = 'abithashenvari2703@gmail.com';
const POINTS_TO_ADD = 1_000_000;
const REASON = 'Manual admin credit — 1,000,000 points via script';

async function main() {
  console.log('Connecting to MongoDB …');
  await mongoose.connect(process.env.MONGO_URI);
  console.log('Connected.\n');

  // 1. Find the user
  const user = await User.findOne({ email: TARGET_EMAIL });
  if (!user) {
    console.error(`❌ No user found with email: ${TARGET_EMAIL}`);
    process.exit(1);
  }
  console.log(`✅ Found user: ${user.name} (${user.email}) — ID: ${user._id}`);

  // 2. Get or create their reward wallet
  let wallet = await Reward.findOne({ user: user._id });
  if (!wallet) {
    wallet = await Reward.create({ user: user._id });
    console.log('   Created new reward wallet.');
  }

  console.log(`   Current balance: ${wallet.availablePoints} available / ${wallet.totalPoints} total (${wallet.tier})`);

  // 3. Add the points via addTransaction (same logic as adminAdjustPoints)
  wallet.addTransaction({
    type: 'adjustment',
    action: 'admin_adjustment',
    points: POINTS_TO_ADD,
    basePoints: POINTS_TO_ADD,
    multiplier: 1,
    description: REASON,
    metadata: { adminId: 'script', note: 'One-off credit via add_points.js' },
  });

  await wallet.save();

  console.log(`\n🎉 Successfully added ${POINTS_TO_ADD.toLocaleString()} points!`);
  console.log(`   New balance: ${wallet.availablePoints.toLocaleString()} available / ${wallet.totalPoints.toLocaleString()} total`);
  console.log(`   Tier: ${wallet.tier}`);

  await mongoose.disconnect();
  console.log('\nDone.');
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(1);
});
