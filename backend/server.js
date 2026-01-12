
console.log("🚀 Server Starting with ALL IMPORTS...");

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
import mongoose from "mongoose";
import morgan from "morgan";
import multer from "multer";
import nodemailer from "nodemailer";
import pdfkit from "pdfkit";
import qrcode from "qrcode";
import speakeasy from "speakeasy";

console.log("✅ All packages imported successfully!");

const app = express();
const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.send(`Hello! Packages are OK.`);
});

app.get("/health", (req, res) => {
  res.json({ status: "ok", message: "Packages OK" });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Test Server running with full imports`);
});