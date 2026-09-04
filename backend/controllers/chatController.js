import Conversation from "../models/Conversation.js";
import Message from "../models/Message.js";
import Property from "../models/Property.js";
import Report from "../models/Report.js";
import User from "../models/userModel.js";
import { notifyUser, pushOnly } from "../services/notificationService.js";
import { leadForConversation, markOwnerResponded } from "./dealController.js";
import { detectLure, LURE_WARNING } from "../utils/scamHeuristics.js";

// H4 FIX: Basic HTML entity escaping to prevent stored XSS
const escapeHtml = (str) => {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
};

// Start or get existing conversation
export const startConversation = async (req, res) => {
  try {
    // H5 FIX: ownerId is NEVER accepted from the client.
    // Always derived from the property's actual owner to prevent IDOR/spam.
    const { propertyId } = req.body;
    // Use _id as the primary, fallback to id for special cases like agent/owner
    const buyerId = req.user._id || req.user.id;

    console.log("Start conversation request:", { propertyId, buyerId });

    // Validate property exists and get owner
    const property = await Property.findById(propertyId).populate("owner", "_id name email");
    if (!property) {
      return res.status(404).json({ success: false, message: "Property not found" });
    }

    // Always derive ownerId from the property — never trust client input
    const ownerId = property.owner?._id?.toString() || property.owner?.toString();

    // Validate ownerId exists
    if (!ownerId) {
      console.error("Property has no owner:", propertyId);
      return res.status(400).json({ 
        success: false, 
        message: "This property has no owner assigned. Cannot start conversation." 
      });
    }

    // Convert to string for comparison
    const ownerIdStr = ownerId.toString();
    const buyerIdStr = buyerId.toString();

    // Can't start conversation with yourself
    if (buyerIdStr === ownerIdStr) {
      return res.status(400).json({ success: false, message: "Cannot start conversation with yourself" });
    }

    // Verify owner exists in database
    const ownerExists = await User.findById(ownerId);
    if (!ownerExists) {
      return res.status(404).json({ success: false, message: "Property owner not found in database" });
    }

    // Check if conversation already exists
    let conversation = await Conversation.findOne({
      participants: { $all: [buyerIdStr, ownerIdStr] },
      property: propertyId,
    });

    if (conversation) {
      // Return existing conversation
      await conversation.populate([
        { path: "participants", select: "name email profileImage" },
        { path: "property", select: "title images address price" },
      ]);
      return res.json({ success: true, conversation, isNew: false });
    }

    // Create new conversation with proper unreadCount initialization
    const unreadCountObj = {};
    unreadCountObj[ownerIdStr] = 0;
    unreadCountObj[buyerIdStr] = 0;

    conversation = new Conversation({
      participants: [buyerIdStr, ownerIdStr],
      property: propertyId,
      unreadCount: unreadCountObj,
    });

    await conversation.save();
    await conversation.populate([
      { path: "participants", select: "name email profileImage" },
      { path: "property", select: "title images address price owner" },
    ]);

    console.log("Conversation created successfully:", conversation._id);
    res.status(201).json({ success: true, conversation, isNew: true });
  } catch (error) {
    console.error("Start conversation error:", error);
    res.status(500).json({ success: false, message: "Failed to start conversation", error: error.message });
  }
};

// Get all conversations for a user
export const getConversations = async (req, res) => {
  try {
    const userId = (req.user._id || req.user.id).toString();

    const conversations = await Conversation.find({
      participants: userId,
      isActive: true,
    })
      .populate("participants", "name email profileImage")
      .populate("property", "title images address price propertyTypeName owner")
      .sort({ updatedAt: -1 });

    // Add other participant info and unread count
    const formattedConversations = conversations.map((conv) => {
      const otherParticipant = conv.participants.find(
        (p) => p._id.toString() !== userId
      );

      const propertyOwner = conv.property?.owner;
      const propertyOwnerId =
        typeof propertyOwner === "string" || !propertyOwner
          ? propertyOwner?.toString?.()
          : propertyOwner._id?.toString?.();

      const isOwner = propertyOwnerId === userId;

      return {
        ...conv.toObject(),
        otherParticipant,
        myUnreadCount: conv.unreadCount.get(userId) || 0,
        isOwner,
      };
    });

    res.json({ success: true, conversations: formattedConversations });
  } catch (error) {
    console.error("Get conversations error:", error);
    res.status(500).json({ success: false, message: "Failed to get conversations" });
  }
};

// Get messages for a conversation
export const getMessages = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = (req.user._id || req.user.id).toString();
    const { page = 1, limit = 50 } = req.query;

    // Verify user is participant
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(404).json({ success: false, message: "Conversation not found" });
    }

    if (!conversation.participants.map(p => p.toString()).includes(userId)) {
      return res.status(403).json({ success: false, message: "Not authorized" });
    }

    const messages = await Message.find({
      conversation: conversationId,
      isDeleted: false,
    })
      .populate("sender", "name email profileImage")
      .sort({ createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(parseInt(limit));

    // Mark messages as read
    await Message.updateMany(
      {
        conversation: conversationId,
        sender: { $ne: userId },
        "readBy.user": { $ne: userId },
      },
      {
        $push: { readBy: { user: userId, readAt: new Date() } },
      }
    );

    // Reset unread count for this user
    conversation.unreadCount.set(userId, 0);
    await conversation.save();

    res.json({ success: true, messages: messages.reverse() });
  } catch (error) {
    console.error("Get messages error:", error);
    res.status(500).json({ success: false, message: "Failed to get messages" });
  }
};

// Send a message
export const sendMessage = async (req, res) => {
  try {
    const { conversationId, text, messageType = "text" } = req.body;
    const senderId = (req.user._id || req.user.id).toString();

    // Verify conversation and user is participant
    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(404).json({ success: false, message: "Conversation not found" });
    }

    if (!conversation.participants.map(p => p.toString()).includes(senderId)) {
      return res.status(403).json({ success: false, message: "Not authorized" });
    }

    // H4 FIX: Sanitize and limit message text to prevent stored XSS
    const sanitizedText = escapeHtml(text?.substring(0, 5000));
    if (!sanitizedText || sanitizedText.trim().length === 0) {
      return res.status(400).json({ success: false, message: "Message text is required" });
    }

    // Create message
    // Only a text message can be sent through this route. The other types
    // are written by the server (system warnings) or reserved.
    const type = messageType === "text" ? "text" : "text";

    // Payment-lure detection (Phase 2, F13). The message still goes through;
    // it is flagged, and a system warning follows it in the thread so BOTH
    // parties see it. The honest owner asking for a token after a visit is
    // not blocked, and the buyer is told what DealDirect never asks for.
    const lure = detectLure(text || "");

    const message = new Message({
      conversation: conversationId,
      sender: senderId,
      text: sanitizedText,
      messageType: type,
      readBy: [{ user: senderId, readAt: new Date() }],
      flags: lure ? [lure.flag] : [],
    });

    await message.save();
    await message.populate("sender", "name email profileImage");

    let warning = null;
    if (lure) {
      warning = await Message.create({
        conversation: conversationId,
        sender: senderId,
        text: LURE_WARNING,
        messageType: "system",
        readBy: [{ user: senderId, readAt: new Date() }],
        flags: ["lure_warning"],
      });
    }

    // Update conversation
    // B3: the preview used to store the RAW text while the message itself
    // stored the escaped one, so a payload that was harmless in the thread was
    // live HTML in the conversation list. Same string, both places.
    conversation.lastMessage = {
      text: sanitizedText,
      sender: senderId,
      createdAt: new Date(),
    };

    // Increment unread count for other participants
    conversation.participants.forEach((participantId) => {
      if (participantId.toString() !== senderId) {
        const currentCount = conversation.unreadCount.get(participantId.toString()) || 0;
        conversation.unreadCount.set(participantId.toString(), currentCount + 1);
      }
    });

    await conversation.save();

    // Deal-room hooks (Phase 2). The first owner message on a lead is the
    // owner's response for the response-time figure and earns the buyer an
    // "owner replied" notification; every other message is a push-only nudge
    // to the recipient, throttled per conversation.
    try {
      const recipientId = conversation.participants.map((p) => p.toString()).find((p) => p !== senderId);
      const lead = await leadForConversation(conversation._id);
      const senderIsOwner = lead ? String(lead.propertyOwner) === senderId : false;
      const senderName = message.sender?.name || "Someone";

      if (lead && senderIsOwner && !lead.firstOwnerResponseAt) {
        await markOwnerResponded(lead);
        await notifyUser(lead.user, {
          title: "The owner replied",
          message: `${senderName} replied about ${lead.propertySnapshot?.title || "the property"}.`,
          type: "owner_replied",
          data: { leadId: lead._id, conversationId: conversation._id, propertyId: lead.property, actionUrl: `/deals/${lead._id}`, actionText: "Open deal" },
        });
      } else if (recipientId) {
        await pushOnly(recipientId, {
          title: senderName,
          body: text.length > 120 ? `${text.slice(0, 117)}...` : text,
          data: { kind: "message", conversationId: String(conversation._id), leadId: lead ? String(lead._id) : undefined },
          throttleKey: `conv:${conversation._id}`,
        });
      }
    } catch (hookErr) {
      console.error("[chat] deal hook failed:", hookErr.message);
    }

    res.status(201).json({ success: true, message, warning, flagged: !!lure });
  } catch (error) {
    console.error("Send message error:", error);
    res.status(500).json({ success: false, message: "Failed to send message" });
  }
};

// Get unread message count
export const getUnreadCount = async (req, res) => {
  try {
    const userId = (req.user._id || req.user.id).toString();

    const conversations = await Conversation.find({
      participants: userId,
      isActive: true,
    });

    let totalUnread = 0;
    conversations.forEach((conv) => {
      totalUnread += conv.unreadCount.get(userId) || 0;
    });

    res.json({ success: true, unreadCount: totalUnread });
  } catch (error) {
    console.error("Get unread count error:", error);
    res.status(500).json({ success: false, message: "Failed to get unread count" });
  }
};

// Delete/Archive conversation
export const deleteConversation = async (req, res) => {
  try {
    const { conversationId } = req.params;
    const userId = (req.user._id || req.user.id).toString();

    const conversation = await Conversation.findById(conversationId);
    if (!conversation) {
      return res.status(404).json({ success: false, message: "Conversation not found" });
    }

    if (!conversation.participants.map(p => p.toString()).includes(userId)) {
      return res.status(403).json({ success: false, message: "Not authorized" });
    }

    // Soft delete - just mark as inactive
    conversation.isActive = false;
    await conversation.save();

    res.json({ success: true, message: "Conversation archived" });
  } catch (error) {
    console.error("Delete conversation error:", error);
    res.status(500).json({ success: false, message: "Failed to delete conversation" });
  }
};


// ============================================
// POST /chat/message/report   { messageId, reason }
//
// Reporting is the other half of the lure detector: heuristics catch the
// obvious shapes, people catch the rest. A participant of the conversation
// may report any message in it that they did not send. One report per
// (reporter, message).
// ============================================
export const reportMessage = async (req, res) => {
  try {
    const reporterId = (req.user._id || req.user.id).toString();
    const { messageId, reason } = req.body || {};

    if (!messageId || typeof messageId !== "string" || messageId.length !== 24) {
      return res.status(400).json({ success: false, code: "INVALID_MESSAGE", message: "messageId is required" });
    }
    const text = typeof reason === "string" ? reason.trim().slice(0, 500) : "";
    if (text.length < 3) {
      return res.status(400).json({ success: false, code: "REASON_REQUIRED", message: "Tell us what is wrong (a few words)" });
    }

    const message = await Message.findById(messageId).select("conversation sender").lean();
    if (!message) return res.status(404).json({ success: false, code: "NOT_FOUND", message: "Message not found" });

    const conversation = await Conversation.findById(message.conversation).select("participants").lean();
    if (!conversation || !conversation.participants.map((p) => p.toString()).includes(reporterId)) {
      return res.status(403).json({ success: false, code: "NOT_A_PARTICIPANT", message: "Not authorized" });
    }
    if (String(message.sender) === reporterId) {
      return res.status(400).json({ success: false, code: "OWN_MESSAGE", message: "You cannot report your own message" });
    }

    const existing = await Report.findOne({ reportedBy: reporterId, message: message._id }).select("_id").lean();
    if (existing) return res.status(200).json({ success: true, data: { reportId: existing._id }, duplicate: true });

    const report = await Report.create({
      reportedBy: reporterId,
      contextType: "message",
      message: message._id,
      conversation: message.conversation,
      reason: text,
    });

    res.status(201).json({ success: true, data: { reportId: report._id } });
  } catch (error) {
    console.error("[chat] report failed:", error);
    res.status(500).json({ success: false, message: "Could not submit the report" });
  }
};
