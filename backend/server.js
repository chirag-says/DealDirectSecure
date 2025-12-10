import dotenv from "dotenv";
dotenv.config(); // Load env vars BEFORE other imports

import express from "express";
import cors from "cors";
import { createServer } from "http";
import { Server } from "socket.io";
import connectDB from "./config/db.js";

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

connectDB();

const app = express();
const httpServer = createServer(app);

// Socket.io setup for real-time chat
const io = new Server(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
});

// Store online users
const onlineUsers = new Map();

io.on("connection", (socket) => {
  console.log("User connected:", socket.id);

  // User joins with their userId
  socket.on("user_online", (userId) => {
    onlineUsers.set(userId, socket.id);
    io.emit("users_online", Array.from(onlineUsers.keys()));
  });

  // Join a conversation room
  socket.on("join_conversation", (conversationId) => {
    socket.join(conversationId);
    console.log(`User ${socket.id} joined conversation ${conversationId}`);
  });

  // Leave a conversation room
  socket.on("leave_conversation", (conversationId) => {
    socket.leave(conversationId);
  });

  // Handle new message
  socket.on("send_message", (data) => {
    const { conversationId, message } = data;
    // Broadcast to all users in the conversation except sender
    socket.to(conversationId).emit("receive_message", message);
  });

  // Handle typing indicator
  socket.on("typing", (data) => {
    const { conversationId, userId, userName } = data;
    socket.to(conversationId).emit("user_typing", { userId, userName });
  });

  // Handle stop typing
  socket.on("stop_typing", (data) => {
    const { conversationId, userId } = data;
    socket.to(conversationId).emit("user_stop_typing", { userId });
  });

  // Handle disconnect
  socket.on("disconnect", () => {
    // Remove user from online users
    for (const [userId, socketId] of onlineUsers.entries()) {
      if (socketId === socket.id) {
        onlineUsers.delete(userId);
        break;
      }
    }
    io.emit("users_online", Array.from(onlineUsers.keys()));
    console.log("User disconnected:", socket.id);
  });
});

app.use(cors({ origin: "*" }));
app.use(express.json());
app.use("/uploads", express.static("uploads")); // serve images

// Routes
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

const PORT = process.env.PORT || 9000;
httpServer.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));