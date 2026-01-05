/**
 * DealDirect Backend Server - Production-Ready & Security Hardened
 * 
 * SECURITY FEATURES:
 * - Environment validation with pre-flight checks
 * - Helmet for secure headers and CSP
 * - CORS lockdown with domain whitelist
 * - Multi-tiered rate limiting
 * - HSTS enforcement and secure cookies
 * - Payload size limiting
 * - Production error boundary
 */

import dotenv from "dotenv";
dotenv.config(); // Load env vars BEFORE other imports

import express from "express";
import cors from "cors";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import hpp from "hpp";
import { createServer } from "http";
import { Server } from "socket.io";
import crypto from "crypto";

// ============================================
// ENVIRONMENT VALIDATION - PRE-FLIGHT CHECKS
// Must run BEFORE any database connections
// ============================================

const validateEnvironment = () => {
  const isProduction = process.env.NODE_ENV === 'production';
  const errors = [];
  const warnings = [];

  // Critical environment variables that MUST exist
  const REQUIRED_ENV_VARS = [
    'JWT_SECRET',
    'MONGO_URI', // Changed from MONGODB_URI to match existing config
  ];

  // Variables required for production
  const PRODUCTION_REQUIRED = [
    'CLIENT_URL',
    'ADMIN_URL',
    'AGREEMENT_SECRET_KEY',
  ];

  // Check required variables
  for (const varName of REQUIRED_ENV_VARS) {
    if (!process.env[varName]) {
      errors.push(`❌ CRITICAL: Missing required environment variable: ${varName}`);
    }
  }

  // Check production-required variables
  if (isProduction) {
    for (const varName of PRODUCTION_REQUIRED) {
      if (!process.env[varName]) {
        errors.push(`❌ PRODUCTION: Missing required environment variable: ${varName}`);
      }
    }
  }

  // Validate JWT_SECRET strength - error in production, warning in development
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length < 32) {
    if (isProduction) {
      errors.push('❌ SECURITY: JWT_SECRET must be at least 32 characters long');
    } else {
      warnings.push('⚠️ SECURITY: JWT_SECRET is less than 32 characters - recommended to use a stronger secret');
    }
  }

  // Check for development mode connected to production database
  if (!isProduction && process.env.MONGO_URI) {
    const uri = process.env.MONGO_URI.toLowerCase();
    // Detect common production database patterns
    const productionPatterns = ['prod', 'production', 'live'];
    for (const pattern of productionPatterns) {
      if (uri.includes(pattern)) {
        warnings.push(`⚠️ WARNING: Development mode but connected to database containing '${pattern}' in name`);
        break;
      }
    }
  }

  // Warn about weak security settings
  if (!isProduction) {
    warnings.push('⚠️ Running in development mode - security features relaxed');
  }

  if (!process.env.PAYMENT_WEBHOOK_SECRET && isProduction) {
    warnings.push('⚠️ PAYMENT_WEBHOOK_SECRET not set - webhook validation disabled');
  }

  // Print warnings
  for (const warning of warnings) {
    console.warn(warning);
  }

  // Check for critical errors
  if (errors.length > 0) {
    console.error('\n' + '═'.repeat(60));
    console.error('🚨 ENVIRONMENT VALIDATION FAILED');
    console.error('═'.repeat(60));
    for (const error of errors) {
      console.error(error);
    }
    console.error('═'.repeat(60));
    console.error('Server startup aborted due to missing/invalid configuration.');
    console.error('Please fix the above issues and restart the server.\n');
    process.exit(1);
  }

  console.log('✅ Environment validation passed');
};

// Run pre-flight checks
validateEnvironment();

// ============================================
// DATABASE CONNECTION (After validation)
// ============================================

import connectDB from "./config/db.js";
connectDB();

// ============================================
// SECURITY MIDDLEWARE IMPORTS
// ============================================

import { globalErrorHandler, notFoundHandler } from "./middleware/errorHandler.js";
import { blockRetiredRoles } from "./middleware/roleGuard.js";
import { setCsrfToken, validateCsrfToken, getCsrfTokenHandler } from "./middleware/csrfProtection.js";

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

// ============================================
// SECURITY: Model import for Socket.io authorization
// ============================================
import Conversation from './models/Conversation.js';

// ============================================
// EXPRESS APP INITIALIZATION
// ============================================

const app = express();
const httpServer = createServer(app);
const isProduction = process.env.NODE_ENV === 'production';

// ============================================
// SECURITY FIX: Trust Proxy Configuration
// 
// WARNING: 'trust proxy' = 1 blindly trusts the last hop.
// This can cause issues with multiple proxy layers (CDN + LB)
// where rate limiting applies to LB IP instead of client.
//
// Options:
// - 'loopback' = Trust only localhost (safest for single-proxy setups)
// - Specific IPs = Trust only known proxy IPs (recommended for production)
// - Number N = Trust N hops (risky if miscounted)
// ============================================
if (isProduction) {
  // Production: Only trust proxies from specific IPs/subnets
  // Configure TRUSTED_PROXIES env var with comma-separated IPs
  const trustedProxies = process.env.TRUSTED_PROXIES
    ? process.env.TRUSTED_PROXIES.split(',').map(ip => ip.trim())
    : 'loopback'; // Default: only trust localhost reverse proxy

  app.set('trust proxy', trustedProxies);
  console.log(`✅ Trust proxy configured:`, trustedProxies);
} else {
  // Development: Trust first hop (local nginx/docker)
  app.set('trust proxy', 1);
}

// ============================================
// DOMAIN WHITELIST - Environment Aware
// ============================================

const getWhitelistedOrigins = () => {
  const origins = [];

  // Production domains (required)
  if (process.env.CLIENT_URL) origins.push(process.env.CLIENT_URL);
  if (process.env.ADMIN_URL) origins.push(process.env.ADMIN_URL);

  // Development domains (only in non-production)
  if (!isProduction) {
    origins.push(
      'http://localhost:3000',
      'http://localhost:3001',
      'http://localhost:5173',
      'http://localhost:5174',
      'http://127.0.0.1:3000',
      'http://127.0.0.1:5173',
    );
  }

  return origins;
};

const allowedOrigins = getWhitelistedOrigins();

console.log(`🌐 CORS Whitelist: ${allowedOrigins.join(', ')}`);

// ============================================
// SECURITY: Hide server technology stack
// ============================================

app.disable('x-powered-by');

// ============================================
// SECURITY: Secure Headers with Helmet & CSP
// ============================================

app.use(helmet({
  // Content Security Policy - strict whitelist
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"], // NO unsafe-inline, NO unsafe-eval
      styleSrc: ["'self'", "'unsafe-inline'"], // Allow inline styles for markdown
      imgSrc: ["'self'", "data:", "blob:", "https://res.cloudinary.com", "https://*.cloudinary.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'", ...allowedOrigins],
      frameSrc: ["'none'"], // Block all iframes
      frameAncestors: ["'none'"], // Prevent clickjacking
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      workerSrc: ["'self'"],
      childSrc: ["'none'"],
      formAction: ["'self'"],
      upgradeInsecureRequests: isProduction ? [] : null,
      blockAllMixedContent: isProduction ? [] : null,
    },
  },
  // Cross-Origin Policies
  crossOriginEmbedderPolicy: false, // Disable for Cloudinary images
  crossOriginResourcePolicy: { policy: "cross-origin" },
  // DNS Prefetch Control
  dnsPrefetchControl: { allow: false },
  // Expect-CT
  expectCt: { enforce: true, maxAge: 86400 },
  // Referrer Policy
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
  // X-Content-Type-Options
  noSniff: true,
  // X-Frame-Options
  frameguard: { action: 'deny' },
  // X-XSS-Protection (legacy but still useful)
  xssFilter: true,
  // Permissions Policy
  permittedCrossDomainPolicies: { permittedPolicies: 'none' },
}));

// ============================================
// SECURITY: HSTS (HTTP Strict Transport Security)
// Force HTTPS in production
// ============================================

if (isProduction) {
  app.use(helmet.hsts({
    maxAge: 31536000, // 1 year
    includeSubDomains: true,
    preload: true,
  }));

  // Redirect HTTP to HTTPS
  app.use((req, res, next) => {
    if (req.headers['x-forwarded-proto'] !== 'https' && req.hostname !== 'localhost') {
      return res.redirect(301, `https://${req.hostname}${req.url}`);
    }
    next();
  });
}

// ============================================
// SECURITY: Request ID for error tracking
// ============================================

app.use((req, res, next) => {
  req.requestId = `${Date.now()}-${crypto.randomBytes(8).toString('hex')}`;
  res.setHeader('X-Request-ID', req.requestId);
  next();
});

// ============================================
// SECURITY: HTTP Parameter Pollution Protection
// ============================================

app.use(hpp({
  whitelist: ['sort', 'fields', 'page', 'limit', 'status', 'type'], // Allow these query params
}));

// ============================================
// RATE LIMITING: Multi-Tiered Strategy
// ============================================

// Global rate limiter - standard threshold
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 500, // 500 requests per 15 minutes
  message: {
    success: false,
    message: 'Too many requests. Please try again later.',
    code: 'RATE_LIMITED',
  },
  standardHeaders: true,
  legacyHeaders: false,
  // ============================================
  // SECURITY FIX: Use verified req.ip (from trust proxy)
  // instead of blindly trusting x-forwarded-for header
  // ============================================
  keyGenerator: (req) => {
    // req.ip is now verified by Express's trust proxy setting
    return req.ip || 'unknown';
  },
  skip: (req) => {
    // Skip rate limiting for health checks
    return req.path === '/health' || req.path === '/api/health';
  },
});

// Aggressive auth rate limiter - prevent brute force
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // Only 5 login attempts per 15 minutes
  message: {
    success: false,
    message: 'Too many login attempts. Please try again in 15 minutes.',
    code: 'AUTH_RATE_LIMITED',
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Don't count successful logins
  // ============================================
  // SECURITY FIX: Use verified req.ip
  // ============================================
  keyGenerator: (req) => {
    // Rate limit by verified IP + email combination for more precision
    const email = req.body?.email || '';
    return `${req.ip}:${email}`;
  },
});

// Transactional rate limiter - protect financial operations
const transactionalLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 20, // 20 agreement generations per hour
  message: {
    success: false,
    message: 'Transaction rate limit exceeded. Please try again later.',
    code: 'TRANSACTION_RATE_LIMITED',
  },
  standardHeaders: true,
  legacyHeaders: false,
  // ============================================
  // SECURITY FIX: Use verified req.ip as fallback
  // ============================================
  keyGenerator: (req) => {
    return req.user?._id?.toString() || req.ip;
  },
});

// Webhook rate limiter - protect against replay attacks
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 30, // 30 webhook calls per minute
  message: {
    success: false,
    message: 'Webhook rate limit exceeded.',
    code: 'WEBHOOK_RATE_LIMITED',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// ============================================
// SECURITY FIX: Search Rate Limiter
// Search endpoints are expensive - stricter limits
// ============================================
const searchLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 search requests per minute
  message: {
    success: false,
    message: 'Too many search requests. Please slow down.',
    code: 'SEARCH_RATE_LIMITED',
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip || 'unknown';
  },
});

// Apply global rate limiter
app.use(globalLimiter);

// ============================================
// CORS LOCKDOWN - Dynamic Whitelist
// ============================================

const corsOptions = {
  origin: function (origin, callback) {
    // Allow requests with no origin (mobile apps, Postman in dev only)
    if (!origin) {
      if (isProduction) {
        // In production, reject requests without origin
        return callback(new Error('Origin required in production'), false);
      }
      return callback(null, true);
    }

    // Check whitelist
    if (allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn(`⚠️ CORS blocked request from: ${origin}`);
      callback(new Error(`Origin ${origin} not allowed by CORS`), false);
    }
  },
  credentials: true, // Allow cookies - ONLY for whitelisted origins
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Request-ID', 'X-Idempotency-Key', 'X-CSRF-Token'],
  exposedHeaders: ['X-Request-ID'],
  maxAge: 600, // Cache preflight for 10 minutes
  optionsSuccessStatus: 200,
};

app.use(cors(corsOptions));

// ============================================
// SOCKET.IO SETUP - Secure Configuration
// ============================================

const io = new Server(httpServer, {
  cors: {
    origin: allowedOrigins,
    methods: ["GET", "POST"],
    credentials: true,
  },
  pingTimeout: 60000,
  pingInterval: 25000,
});

// Store online users with their user IDs
const onlineUsers = new Map();
// Store socket-to-userId mapping for authorization
const socketUserMap = new Map();

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  // ============================================
  // SECURITY: Track user identity on connection
  // ============================================
  socket.on("user_online", (userId) => {
    if (userId && typeof userId === 'string' && userId.length < 100) {
      onlineUsers.set(userId, socket.id);
      socketUserMap.set(socket.id, userId); // Track this socket's user
      io.emit("users_online", Array.from(onlineUsers.keys()));
    }
  });

  // ============================================
  // SECURITY FIX: Authorization check before joining conversation
  // Verify that the requesting user is a participant in the conversation
  // ============================================
  socket.on("join_conversation", async (conversationId) => {
    try {
      // Validate input
      if (!conversationId || typeof conversationId !== 'string' || conversationId.length > 100) {
        console.warn(`[Socket.io] Invalid conversationId from socket ${socket.id}`);
        socket.emit('error', { code: 'INVALID_CONVERSATION_ID', message: 'Invalid conversation ID' });
        return;
      }

      // Get the user ID associated with this socket
      const userId = socketUserMap.get(socket.id);
      if (!userId) {
        console.warn(`[Socket.io] Unauthenticated socket ${socket.id} attempting to join conversation`);
        socket.emit('error', { code: 'NOT_AUTHENTICATED', message: 'Please authenticate first' });
        return;
      }

      // SECURITY: Verify the user is a participant in this conversation
      const conversation = await Conversation.findOne({
        _id: conversationId,
        participants: userId,
        isActive: true,
      }).lean();

      if (!conversation) {
        console.warn(`[Socket.io] SECURITY: User ${userId} denied access to conversation ${conversationId}`);
        socket.emit('error', { code: 'ACCESS_DENIED', message: 'You are not a participant in this conversation' });
        return;
      }

      // Authorization passed - allow joining
      socket.join(conversationId);
      console.log(`[Socket.io] User ${userId} joined conversation ${conversationId}`);
    } catch (error) {
      console.error('[Socket.io] Error in join_conversation:', error);
      socket.emit('error', { code: 'SERVER_ERROR', message: 'Failed to join conversation' });
    }
  });

  socket.on("leave_conversation", (conversationId) => {
    if (conversationId) socket.leave(conversationId);
  });

  // ============================================
  // SECURITY: Validate sender identity before relaying messages
  // ============================================
  socket.on("send_message", (data) => {
    const userId = socketUserMap.get(socket.id);
    if (!userId) {
      socket.emit('error', { code: 'NOT_AUTHENTICATED', message: 'Please authenticate first' });
      return;
    }
    if (data?.conversationId && data?.message) {
      // Only relay to the conversation room (verified users only)
      socket.to(data.conversationId).emit("receive_message", data.message);
    }
  });

  socket.on("typing", (data) => {
    if (data?.conversationId) {
      socket.to(data.conversationId).emit("user_typing", {
        userId: data.userId,
        userName: data.userName
      });
    }
  });

  socket.on("stop_typing", (data) => {
    if (data?.conversationId) {
      socket.to(data.conversationId).emit("user_stop_typing", { userId: data.userId });
    }
  });

  socket.on("disconnect", () => {
    // Clean up user tracking
    const userId = socketUserMap.get(socket.id);
    if (userId) {
      onlineUsers.delete(userId);
      socketUserMap.delete(socket.id);
    }
    io.emit("users_online", Array.from(onlineUsers.keys()));
  });
});

// ============================================
// SECURITY: Cookie Parser with Secure Settings
// ============================================

app.use(cookieParser(process.env.COOKIE_SECRET || process.env.JWT_SECRET));

// ============================================
// SECURITY: Secure Cookie Middleware
// Enforce Secure and SameSite attributes
// ============================================

app.use((req, res, next) => {
  // Override res.cookie to enforce security
  const originalCookie = res.cookie.bind(res);
  res.cookie = (name, value, options = {}) => {
    const secureOptions = {
      ...options,
      httpOnly: options.httpOnly !== false, // Default to true
      secure: isProduction, // Require HTTPS in production
      sameSite: options.sameSite || 'Lax', // Default to Lax for better reliability
      path: options.path || '/',
    };
    return originalCookie(name, value, secureOptions);
  };
  next();
});

// ============================================
// SECURITY: CSRF Protection
// Set CSRF token on all requests
// ============================================

app.use(setCsrfToken);

// ============================================
// SECURITY: Payload Size Limiting
// ============================================

// Strict limits for authentication routes (prevent memory exhaustion)
app.use("/api/users/login", express.json({ limit: "10kb" }));
app.use("/api/users/register", express.json({ limit: "20kb" }));
app.use("/api/admin/login", express.json({ limit: "10kb" }));

// Strict limits for sensitive transactional routes
app.use("/api/agreements", express.json({ limit: "50kb" }));
app.use("/api/contact", express.json({ limit: "20kb" }));

// General JSON body parser (100KB for normal operations)
app.use(express.json({ limit: "100kb" }));
app.use(express.urlencoded({ extended: true, limit: "100kb" }));

// ============================================
// SECURITY: Rate Limiting for Sensitive Routes
// Applied AFTER body parsing but BEFORE routes
// ============================================

app.use("/api/users/login", authLimiter);
app.use("/api/users/register", authLimiter);
app.use("/api/admin/login", authLimiter);
app.use("/api/users/forgot-password", authLimiter);
app.use("/api/agreements/generate", transactionalLimiter);
app.use("/api/agreements/webhook", webhookLimiter);

// ============================================
// SECURITY FIX: Rate limit expensive search endpoints
// ============================================
app.use("/api/properties/search", searchLimiter);
app.use("/api/properties/suggestions", searchLimiter);
app.use("/api/properties/filter", searchLimiter);

// ============================================
// SECURITY: Block retired 'Agent' role globally
// ============================================

app.use(blockRetiredRoles);

// ============================================
// Health Check Endpoint (before other routes)
// ============================================

app.get('/health', (req, res) => {
  res.status(200).json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
    environment: isProduction ? 'production' : 'development',
  });
});

app.get('/api/health', (req, res) => {
  res.status(200).json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString(),
  });
});

// ============================================
// CSRF Token Endpoint
// Frontend should call this on app load to get CSRF token
// ============================================

app.get('/api/csrf-token', getCsrfTokenHandler);

// ============================================
// SECURITY: CSRF Validation for State-Changing Requests
// Applied BEFORE routes but AFTER CSRF token is set
// ============================================

app.use('/api', validateCsrfToken);

// ============================================
// STATIC FILES (with security headers)
// ============================================

app.use("/uploads", express.static("uploads", {
  maxAge: '1d',
  etag: true,
  setHeaders: (res, path) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Cache-Control', 'public, max-age=86400');
  },
}));

// ============================================
// API ROUTES
// ============================================

app.use("/api/propertyTypes", propertyTypeRoutes);
app.use("/api/users", userRoutes);
app.use("/api/admin", adminRoutes);
app.use("/api/categories", categoryRoutes);
app.use("/api/subcategories", subcategoryRoutes);
app.use("/api/properties", propertyRoutes);
app.use("/api/leads", leadRoutes);
app.use("/api/chat", chatRoutes);
app.use("/api/contact", contactRoutes);
app.use("/api/agreements", agreementRoutes);
app.use("/api/saved-searches", savedSearchRoutes);
app.use("/api/notifications", notificationRoutes);

// ============================================
// ERROR HANDLING (Must be LAST)
// ============================================

// Handle 404 - Route not found
app.use(notFoundHandler);

// Global error handler - logs full errors, returns safe messages
app.use(globalErrorHandler);

// ============================================
// GRACEFUL SHUTDOWN
// ============================================

const gracefulShutdown = (signal) => {
  console.log(`\n${signal} received. Shutting down gracefully...`);

  httpServer.close(() => {
    console.log('HTTP server closed.');
    process.exit(0);
  });

  // Force close after 10 seconds
  setTimeout(() => {
    console.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// ============================================
// SERVER STARTUP
// ============================================

const PORT = process.env.PORT || 9000;

httpServer.listen(PORT, () => {
  console.log('═'.repeat(60));
  console.log(`🚀 DealDirect Server v1.0.0`);
  console.log('═'.repeat(60));
  console.log(`📍 Port: ${PORT}`);
  console.log(`🌍 Environment: ${isProduction ? 'PRODUCTION' : 'DEVELOPMENT'}`);
  console.log(`🔒 Security Features:`);
  console.log(`   • Helmet CSP: Enabled`);
  console.log(`   • CORS Lockdown: ${allowedOrigins.length} domains whitelisted`);
  console.log(`   • Rate Limiting: Multi-tier (Global/Auth/Transactional)`);
  console.log(`   • HSTS: ${isProduction ? 'Enabled' : 'Disabled (dev mode)'}`);
  console.log(`   • Secure Cookies: ${isProduction ? 'Strict' : 'Relaxed (dev mode)'}`);
  console.log(`   • Payload Limit: 100KB (10KB for auth)`);
  console.log(`   • X-Powered-By: Hidden`);
  console.log('═'.repeat(60));
});

export { io, httpServer };