/**
 * DealDirect Server - MIDDLEWARE TEST MODE
 * Verifying if middleware or route imports are the cause of the crash.
 */

console.log(" Server starting...");

import jwt from "jsonwebtoken";
import mongoose from "mongoose";
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

// SAFELY connect to database without crashing server
// If connection fails, server stays UP but DB features won't work
connectDB().catch(err => {
  console.error("❌ CRITICAL DATABASE ERROR:", err);
  console.error("⚠️ Server running in 'Offline Mode' (No Database)");
});

// ============================================
// ROUTE IMPORTS
// ============================================

import userRoutes from "./routes/userRoutes.js";
import adminRoutes from "./routes/adminRoutes.js";
import categoryRoutes from "./routes/categoryRoutes.js";
import subcategoryRoutes from "./routes/subcategoryRoutes.js";
import propertyRoutes from "./routes/propertyRoutes.js";
import propertyTypeRoutes from './routes/propertyTypeRoutes.js';
import leadRoutes from './routes/leadRoutes.js';
import chatRoutes from './routes/chatRoutes.js';
import contactRoutes from './routes/contactRoutes.js';
import agreementRoutes from './routes/agreementRoutes.js';
import savedSearchRoutes from './routes/savedSearchRoutes.js';
import notificationRoutes from './routes/notificationRoutes.js';
import { globalErrorHandler, notFoundHandler } from "./middleware/errorHandler.js";
import { blockRetiredRoles } from "./middleware/roleGuard.js";
import { setCsrfToken, validateCsrfToken, getCsrfTokenHandler } from "./middleware/csrfProtection.js";

// ============================================
// APP SETUP & MIDDLEWARE
// ============================================
// (Already configured in previous step)


// ============================================
// API ROUTES
// ============================================

app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    env: process.env.NODE_ENV
  });
});

// DB Diagnostic Endpoint
app.get('/api/health-db', (req, res) => {
  try {
    const statusMap = { 0: 'disconnected', 1: 'connected', 2: 'connecting', 3: 'disconnecting' };
    const state = mongoose.connection ? mongoose.connection.readyState : 99;

    res.json({
      status: 'ok',
      mongo_uri_configured: !!process.env.MONGO_URI,
      // mongo_uri_prefix: process.env.MONGO_URI ? process.env.MONGO_URI.substring(0, 15) + '...' : 'MISSING', // Hidden for security in logs
      dbState: statusMap[state] || 'unknown',
      dbName: mongoose.connection ? mongoose.connection.name : 'unknown',
      host: mongoose.connection ? mongoose.connection.host : 'unknown'
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/csrf-token', getCsrfTokenHandler);

// Root Route (Must be before error handlers)
app.get('/', (req, res) => {
  res.send(`DealDirect Backend v3.0 - FULL SYSTEM ACTIVE (${new Date().toISOString()})`);
});

// Public Routes
app.use("/api/users", userRoutes);
app.use("/api/admin", adminRoutes);

app.use("/api/propertyTypes", propertyTypeRoutes);
app.use("/api/categories", categoryRoutes);
app.use("/api/subcategories", subcategoryRoutes);
app.use("/api/properties", propertyRoutes);
app.use("/api/leads", leadRoutes);
// app.use("/api/chat", chatRoutes); // Disabled until Socket.io is back
app.use("/api/contact", contactRoutes);
app.use("/api/agreements", agreementRoutes);
app.use("/api/saved-searches", savedSearchRoutes);
app.use("/api/notifications", notificationRoutes);

// Error Handling
app.use(notFoundHandler);
app.use(globalErrorHandler);


// ============================================
// STARTUP
// ============================================

const PORT = process.env.PORT || 9000;
httpServer.listen(PORT, '0.0.0.0', () => {
  console.log('═'.repeat(60));
  console.log(`🚀 DealDirect Backend v2.0 - LIVE & HEALTHY`);
  console.log(`👉 Health: http://0.0.0.0:${PORT}/health`);
  console.log('═'.repeat(60));
});