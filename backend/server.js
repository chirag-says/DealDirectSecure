/**
 * DealDirect Backend Server - SAFE MODE RECOVERY
 */

console.log("🚀 Server starting...");
console.log("📍 Node version:", process.version);
console.log("📍 Environment:", process.env.NODE_ENV || 'development');

import dotenv from "dotenv";
dotenv.config();

import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import hpp from "hpp";
import { createServer } from "http";
import { Server } from "socket.io";
import crypto from "crypto";
import jwt from "jsonwebtoken";

// ============================================
// ENVIRONMENT VALIDATION - PRE-FLIGHT CHECKS
// ============================================

const validateEnvironment = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  const errors = [];
  const REQUIRED_ENV_VARS = ['JWT_SECRET', 'MONGO_URI'];

  for (const varName of REQUIRED_ENV_VARS) {
    if (!process.env[varName]) {
      errors.push(`❌ CRITICAL: Missing required environment variable: ${varName}`);
    }
  }

  if (errors.length > 0) {
    console.error('🚨 ENVIRONMENT VALIDATION FAILED');
    errors.forEach(e => console.error(e));
    // process.exit(1); // DISABLED FOR DEBUGGING
    console.error('⚠️ IGNORING FATAL ERRORS FOR DEBUGGING - Server continuing...');
  } else {
    console.log('✅ Environment validation passed');
  }
};

validateEnvironment();

// ============================================
// DATABASE CONNECTION
// ============================================

import connectDB from "./config/db.js";
connectDB(); // Ensure config/db.js does not process.exit(1)!

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
// APP SETUP
// ============================================

const app = express();
const httpServer = createServer(app);
const isProduction = process.env.NODE_ENV === 'production';

// Trust Proxy
if (isProduction) {
  app.set('trust proxy', process.env.TRUSTED_PROXIES || 'loopback');
} else {
  app.set('trust proxy', 1);
}

// CORS
const allowedOrigins = [
  process.env.CLIENT_URL,
  process.env.ADMIN_URL,
  'http://localhost:3000',
  'http://localhost:3001',
  'http://localhost:5173',
  'http://localhost:5174'
].filter(Boolean);

console.log(`🌐 CORS Whitelist: ${allowedOrigins.join(', ')}`);

app.use(cors({
  origin: function (origin, callback) {
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`⚠️ CORS blocked request from: ${origin}`);
      callback(new Error('Not allowed by CORS'), false);
    }
  },
  credentials: true,
}));

// Security Headers
app.use(helmet({
  contentSecurityPolicy: false, // Relax CSP for debugging
  crossOriginResourcePolicy: { policy: "cross-origin" },
}));

app.disable('x-powered-by');

// Middleware
app.use(express.json({ limit: "50kb" }));
app.use(express.urlencoded({ extended: true, limit: "50kb" }));
app.use(cookieParser(process.env.JWT_SECRET));
app.use(hpp());

// ============================================
// SOCKET.IO - DISABLED TEMPORARILY
// ============================================
/* 
const io = new Server(httpServer, {
  cors: { origin: allowedOrigins, methods: ["GET", "POST"], credentials: true }
});
io.on("connection", (socket) => { console.log("User connected:", socket.id); });
*/
// Mock IO
const io = { on: () => { }, emit: () => { }, to: () => ({ emit: () => { } }) };
export { io, httpServer };

// ============================================
// ROUTES & CSRF
// ============================================

app.get('/health', (req, res) => {
  res.status(200).json({ status: 'healthy', env: process.env.NODE_ENV || 'dev' });
});
app.get('/api/health', (req, res) => res.status(200).json({ status: 'healthy' }));

app.use(setCsrfToken);
app.get('/api/csrf-token', getCsrfTokenHandler);

// Public Routes (No CSRF/Auth checks logic here yet, assuming middleware handles it)
app.use("/api/users", userRoutes); // Login/Register likely here
app.use("/api/admin", adminRoutes);

// Protected Routes (Apply CSRF check)
app.use('/api', validateCsrfToken);

app.use("/api/propertyTypes", propertyTypeRoutes);
app.use("/api/categories", categoryRoutes);
app.use("/api/subcategories", subcategoryRoutes);
app.use("/api/properties", propertyRoutes);
app.use("/api/leads", leadRoutes);
app.use("/api/chat", chatRoutes); // Chat routes might break without IO, but app won't crash
app.use("/api/contact", contactRoutes);
app.use("/api/agreements", agreementRoutes);
app.use("/api/saved-searches", savedSearchRoutes);
app.use("/api/notifications", notificationRoutes);

app.use(notFoundHandler);
app.use(globalErrorHandler);

// ============================================
// STARTUP
// ============================================

const PORT = process.env.PORT || 9000;

httpServer.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 DealDirect SAFE Server running on port ${PORT}`);
  console.log(`👉 Health check: http://0.0.0.0:${PORT}/health`);
});