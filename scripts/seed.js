/**
 * Seed Script
 * ---
 * Creates default demo accounts for the Zero Trust Demo.
 * Run with: npm run seed
 */
require('dotenv').config();

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/zero_trust_demo';

const DEFAULT_USERS = [
  { email: 'superadmin@demo.com', password: 'Password@123', role: 'superadmin' },
  { email: 'admin@demo.com',      password: 'Password@123', role: 'admin' },
  { email: 'supervisor@demo.com', password: 'Password@123', role: 'supervisor' },
  { email: 'user@demo.com',       password: 'Password@123', role: 'user' }
];

async function seed() {
  try {
    await mongoose.connect(MONGO_URI);
    console.log('Connected to MongoDB');

    for (const u of DEFAULT_USERS) {
      const exists = await User.findOne({ email: u.email });
      if (exists) {
        console.log(`  ⏭  ${u.email} already exists (role: ${exists.role})`);
        continue;
      }

      const passwordHash = await bcrypt.hash(u.password, 12);
      await User.create({
        email: u.email,
        passwordHash,
        role: u.role,
        status: 'active'
      });
      console.log(`  ✅ Created ${u.email} (role: ${u.role})`);
    }

    console.log('');
    console.log('Seed complete! Default accounts:');
    console.log('──────────────────────────────────────');
    console.log('  superadmin@demo.com  / Password@123');
    console.log('  admin@demo.com       / Password@123');
    console.log('  supervisor@demo.com  / Password@123');
    console.log('  user@demo.com        / Password@123');
    console.log('──────────────────────────────────────');
    console.log('');

    await mongoose.disconnect();
    process.exit(0);
  } catch (err) {
    console.error('Seed error:', err);
    process.exit(1);
  }
}

seed();
