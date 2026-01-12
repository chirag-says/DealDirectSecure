/**
 * DealDirect Server - MIDDLEWARE TEST MODE
 * Verifying if middleware or route imports are the cause of the crash.
 */

console.log("� Server starting...");

import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import hpp from "hpp";
import { createServer } from "http";
import crypto from "crypto";

// ============================================
// APP SETUP
// ============================================

const app = express();
const httpServer = createServer(app);

// MIDDLEWARE SETUP
app.use(helmet({ contentSecurityPolicy: false })); // Relaxed for test
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(hpp());

// CORS
const allowedOrigins = [process.env.CLIENT_URL, process.env.ADMIN_URL, 'http://localhost:3000'].filter(Boolean);
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
    callback(null, true); // Allow all for this test to be safe
  },
  credentials: true
}));

console.log("✅ Middleware configured");

// ============================================
// ENVIRONMENT VALIDATION - PRE-FLIGHT CHECKS
// ============================================

const validateEnvironment = () => {
  const REQUIRED_ENV_VARS = ['JWT_SECRET', 'MONGO_URI'];
  const errors = [];
  for (const varName of REQUIRED_ENV_VARS) {
    if (!process.env[varName]) errors.push(`❌ Missing: ${varName}`);
  }
  if (errors.length > 0) {
    console.error('🚨 Validation Failed:', errors);
    // process.exit(1); // DISABLED
    console.error('⚠️ IGNORING ERRORS FOR DEBUGGING');
  } else {
    console.log('✅ Env validation passed');
  }
};
validateEnvironment();

// ============================================
// DATABASE
// ============================================
import connectDB from "./config/db.js";
connectDB();

// ============================================
// ROUTES - ALL COMMENTED OUT
// The crash is likely inside one of these files!
// ============================================

/*
import userRoutes from "./routes/userRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import categoryRoutes from "./routes/categoryRoutes.js";
import subcategoryRoutes from "./routes/subcategoryRoutes.js";
import propertyRoutes from "./routes/propertyRoutes.js";
// ...
// app.use("/api/users", userRoutes);
*/

app.get('/', (req, res) => {
  res.send('DealDirect Middleware Test - Server is UP!');
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', step: 'middleware_test' });
});

// ============================================
// STARTUP
// ============================================
const PORT = process.env.PORT || 9000;
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Middleware Test Server running on port ${PORT}`);
});