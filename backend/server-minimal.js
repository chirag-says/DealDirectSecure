
console.log("🚀 Minimal Server Starting...");

import express from "express";
const app = express();
const PORT = process.env.PORT || 3000;

app.get("/", (req, res) => {
    res.send("Hello from DealDirect Minimal Server!");
});

app.get("/health", (req, res) => {
    res.json({ status: "ok", message: "Server is compatible with Hostinger!" });
});

app.listen(PORT, () => {
    console.log(`✅ Minimal Server running on port ${PORT}`);
});
