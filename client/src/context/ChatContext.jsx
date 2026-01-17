import React, { createContext, useContext, useState, useEffect, useCallback } from "react";
import { io } from "socket.io-client";
import api from "../utils/api";
import { useAuth } from "./AuthContext";

// Get Socket.io base URL (without /api suffix)
const getSocketBaseUrl = () => {
  if (import.meta.env.VITE_API_BASE) {
    return import.meta.env.VITE_API_BASE;
  }
  // Fallback for development
  return `${window.location.protocol}//${window.location.hostname}:9000`;
};

const API_BASE = getSocketBaseUrl();

const ChatContext = createContext();

export const useChat = () => {
  const context = useContext(ChatContext);
  if (!context) {
    throw new Error("useChat must be used within a ChatProvider");
  }
  return context;
};

export const ChatProvider = ({ children }) => {
  const [socket, setSocket] = useState(null);
  const [conversations, setConversations] = useState([]);
  const [currentConversation, setCurrentConversation] = useState(null);
  const [messages, setMessages] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [isTyping, setIsTyping] = useState(null);
  const [loading, setLoading] = useState(false);
  const [isChatOpen, setIsChatOpen] = useState(false);

  // Use AuthContext for authentication state
  const { user, isAuthenticated } = useAuth();

  // Initialize socket connection
  useEffect(() => {
    if (!isAuthenticated || !user) {
      if (socket) {
        socket.disconnect();
        setSocket(null);
        setConversations([]);
        setMessages([]);
        setUnreadCount(0);
      }
      return;
    }

    // If socket already exists, disconnect before creating new one
    if (socket) {
      socket.disconnect();
    }

    const newSocket = io(API_BASE, {
      transports: ["websocket", "polling"],
      withCredentials: true, // Important for cookie auth
    });

    newSocket.on("connect", async () => {
      console.log("Socket connected");

      // ============================================
      // SECURITY FIX: Use JWT authentication instead of raw userId
      // Request a socket token from the server and authenticate
      // ============================================
      try {
        const res = await api.get('/chat/socket-token');
        if (res.data.success && res.data.token) {
          newSocket.emit("authenticate", { token: res.data.token });
        }
      } catch (error) {
        console.warn("Failed to get socket auth token:", error.message);
        // Fallback: Try with user ID for backward compatibility
        // This will trigger a warning on the server but won't authenticate
        if (user._id) {
          newSocket.emit("user_online", user._id);
        }
      }
    });

    // Handle authentication success
    newSocket.on("authenticated", ({ userId }) => {
      console.log("Socket authenticated for user:", userId);
    });

    // Handle authentication errors
    newSocket.on("auth_error", ({ code, message }) => {
      console.error("Socket authentication error:", code, message);
    });

    // Handle auth required (old method deprecated)
    newSocket.on("auth_required", ({ message }) => {
      console.warn("Socket auth required:", message);
    });

    newSocket.on("users_online", (users) => {
      setOnlineUsers(users);
    });

    newSocket.on("receive_message", (message) => {
      setMessages((prev) => [...prev, message]);
      // Update conversation list
      fetchConversations();
    });

    newSocket.on("user_typing", ({ userId, userName }) => {
      setIsTyping({ userId, userName });
    });

    newSocket.on("user_stop_typing", () => {
      setIsTyping(null);
    });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, [isAuthenticated, user?._id]);

  // Fetch conversations - uses cookie-based auth via api.js
  const fetchConversations = useCallback(async () => {
    if (!isAuthenticated) return;

    try {
      const res = await api.get('/chat/conversations');
      if (res.data.success) {
        setConversations(res.data.conversations);
      }
    } catch (error) {
      console.error("Error fetching conversations:", error);
    }
  }, [isAuthenticated]);

  // Fetch unread count
  const fetchUnreadCount = useCallback(async () => {
    if (!isAuthenticated) return;

    try {
      const res = await api.get('/chat/unread-count');
      if (res.data.success) {
        setUnreadCount(res.data.unreadCount);
      }
    } catch (error) {
      console.error("Error fetching unread count:", error);
    }
  }, [isAuthenticated]);

  // Fetch messages for a conversation
  const fetchMessages = useCallback(async (conversationId) => {
    if (!isAuthenticated) return;

    setLoading(true);
    try {
      const res = await api.get(`/chat/messages/${conversationId}`);
      if (res.data.success) {
        setMessages(res.data.messages);
      }
    } catch (error) {
      console.error("Error fetching messages:", error);
    } finally {
      setLoading(false);
    }
  }, [isAuthenticated]);

  // Start or get conversation
  const startConversation = useCallback(async (propertyId, ownerId) => {
    if (!isAuthenticated) return null;

    try {
      const res = await api.post('/chat/conversation/start', { propertyId, ownerId });
      if (res.data.success) {
        fetchConversations();
        return res.data.conversation;
      }
    } catch (error) {
      console.error("Error starting conversation:", error);
      return null;
    }
  }, [fetchConversations, isAuthenticated]);

  // Send a standard text message
  const sendMessage = useCallback(async (conversationId, text) => {
    if (!isAuthenticated) return null;

    try {
      const res = await api.post('/chat/message/send', { conversationId, text });
      if (res.data.success) {
        const newMessage = res.data.message;
        setMessages((prev) => [...prev, newMessage]);

        // Emit to socket
        if (socket) {
          socket.emit("send_message", { conversationId, message: newMessage });
        }

        fetchConversations();
        return newMessage;
      }
    } catch (error) {
      console.error("Error sending message:", error);
      return null;
    }
  }, [socket, fetchConversations, isAuthenticated]);

  // Send a special visit-related message (request or confirmation)
  const sendVisitMessage = useCallback(
    async (conversationId, text, messageType) => {
      if (!isAuthenticated) return null;

      try {
        const res = await api.post('/chat/message/send', { conversationId, text, messageType });
        if (res.data.success) {
          const newMessage = res.data.message;
          setMessages((prev) => [...prev, newMessage]);

          if (socket) {
            socket.emit("send_message", { conversationId, message: newMessage });
          }

          fetchConversations();
          return newMessage;
        }
      } catch (error) {
        console.error("Error sending visit message:", error);
        return null;
      }
    },
    [socket, fetchConversations, isAuthenticated]
  );

  // Join conversation room
  const joinConversation = useCallback((conversationId) => {
    if (socket) {
      socket.emit("join_conversation", conversationId);
    }
  }, [socket]);

  // Leave conversation room
  const leaveConversation = useCallback((conversationId) => {
    if (socket) {
      socket.emit("leave_conversation", conversationId);
    }
  }, [socket]);

  // Emit typing
  const emitTyping = useCallback((conversationId) => {
    if (socket && user) {
      socket.emit("typing", { conversationId, userId: user._id, userName: user.name });
    }
  }, [socket, user]);

  // Emit stop typing
  const emitStopTyping = useCallback((conversationId) => {
    if (socket && user) {
      socket.emit("stop_typing", { conversationId, userId: user._id });
    }
  }, [socket, user]);

  // Report message
  const reportMessage = useCallback(async (messageId, reason) => {
    if (!isAuthenticated) return null;

    try {
      const res = await api.post('/chat/message/report', { messageId, reason });
      return res.data;
    } catch (error) {
      console.error("Error reporting message:", error);
      return { success: false, message: error.response?.data?.message || "Failed to report" };
    }
  }, [isAuthenticated]);

  // Open chat with a conversation
  const openChat = useCallback((conversation = null) => {
    setCurrentConversation(conversation);
    setIsChatOpen(true);
    if (conversation) {
      fetchMessages(conversation._id);
      joinConversation(conversation._id);
    }
  }, [fetchMessages, joinConversation]);

  // Close chat
  const closeChat = useCallback(() => {
    if (currentConversation) {
      leaveConversation(currentConversation._id);
    }
    setIsChatOpen(false);
    setCurrentConversation(null);
    setMessages([]);
  }, [currentConversation, leaveConversation]);

  // Check if user is online
  const isUserOnline = useCallback((userId) => {
    return onlineUsers.includes(userId);
  }, [onlineUsers]);

  // Initial fetch
  useEffect(() => {
    if (isAuthenticated) {
      fetchConversations();
      fetchUnreadCount();
    } else {
      setConversations([]);
      setUnreadCount(0);
    }
  }, [fetchConversations, fetchUnreadCount, isAuthenticated]);

  // Poll for unread count
  useEffect(() => {
    if (!isAuthenticated) return;

    const interval = setInterval(() => {
      fetchUnreadCount();
    }, 30000); // Every 30 seconds

    return () => clearInterval(interval);
  }, [fetchUnreadCount, isAuthenticated]);

  const value = {
    socket,
    conversations,
    currentConversation,
    messages,
    unreadCount,
    onlineUsers,
    isTyping,
    loading,
    isChatOpen,
    fetchConversations,
    fetchUnreadCount,
    fetchMessages,
    startConversation,
    sendMessage,
    sendVisitMessage,
    joinConversation,
    leaveConversation,
    emitTyping,
    emitStopTyping,
    reportMessage,
    openChat,
    closeChat,
    isUserOnline,
    setCurrentConversation,
  };

  return <ChatContext.Provider value={value}>{children}</ChatContext.Provider>;
};

export default ChatContext;
