
console.log("🚀 Minimal Server Starting...");
console.log("📍 Node Version:", process.version);
console.log("📍 ENV PORT:", process.env.PORT);

import express from "express";
const app = express();

// Hostinger often uses 3000 but passing it via env matches their internal routing
const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
  res.send(`Hello from DealDirect Minimal Server! Running on port ${PORT}`);
});

app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    message: "Server is compatible with Hostinger!",
    env: process.env.NODE_ENV,
    port: PORT
  });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`✅ Minimal Server running on port ${PORT}`);
});

// Handle startup errors
server.on('error', (e) => {
  console.error("❌ Server Error:", e);
});
