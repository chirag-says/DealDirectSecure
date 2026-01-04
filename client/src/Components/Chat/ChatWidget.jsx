import React, { useState, useEffect, useRef } from "react";
import { useChat } from "../../context/ChatContext";
import { useAuth } from "../../context/AuthContext";
import {
  XMarkIcon,
  PaperAirplaneIcon,
  ChatBubbleLeftRightIcon,
  ArrowLeftIcon,
  UserCircleIcon,
  FlagIcon,
  PlusIcon,
} from "@heroicons/react/24/outline";
import { formatDistanceToNow } from "date-fns";
import { toast } from "react-toastify";
import VisitModal from "../VisitModal/VisitModal";

const API_BASE = import.meta.env.VITE_API_BASE;

// Chat Message Component
const ChatMessage = ({ message, isOwn, onReport, canAcceptVisit, onAcceptVisit }) => {
  const formatTime = (date) => {
    return new Date(date).toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
    });
  };

  return (
    <div className={`flex ${isOwn ? "justify-end" : "justify-start"} mb-3 group`}>
      <div
        className={`max-w-[75%] relative px-4 py-2.5 rounded-2xl ${isOwn
          ? "bg-blue-600 text-white rounded-br-md"
          : "bg-gray-100 text-gray-900 rounded-bl-md"
          }`}
      >
        {!isOwn && (
          <button
            onClick={() => onReport(message)}
            className="absolute -right-8 top-1/2 -translate-y-1/2 p-1.5 text-gray-300 hover:text-red-500 hover:bg-red-50 rounded-full opacity-0 group-hover:opacity-100 transition-all"
            title="Report Message"
          >
            <FlagIcon className="w-4 h-4" />
          </button>
        )}
        <p className="text-sm leading-relaxed whitespace-pre-wrap break-words">
          {message.text}
        </p>

        {/* Visit request actions for property owner */}
        {message.messageType === "visit_request" && !isOwn && canAcceptVisit && (
          <button
            onClick={() => onAcceptVisit && onAcceptVisit(message)}
            className="mt-2 inline-flex items-center gap-1.5 text-[11px] font-semibold px-2.5 py-1.5 rounded-full bg-emerald-600 text-white hover:bg-emerald-700 transition"
          >
            Accept Visit
          </button>
        )}
        <p
          className={`text-[10px] mt-1 ${isOwn ? "text-blue-100" : "text-gray-500"
            }`}
        >
          {formatTime(message.createdAt)}
        </p>
      </div>
    </div>
  );
};

// Conversation List Item
const ConversationItem = ({ conversation, isActive, onClick }) => {
  const buildImageUrl = (img) => {
    if (!img) return "";
    if (img.startsWith("http")) return img;
    if (img.startsWith("/uploads")) return `${API_BASE}${img}`;
    return `${API_BASE}/uploads/${img}`;
  };

  const propertyImage =
    conversation.property?.images?.[0] ||
    (conversation.property?.categorizedImages?.residential?.exterior?.[0]);

  return (
    <div
      onClick={onClick}
      className={`flex items-center gap-3 p-3 cursor-pointer transition-all border-b border-gray-100 hover:bg-gray-50 ${isActive ? "bg-blue-50 border-l-4 border-l-blue-600" : ""
        }`}
    >
      {/* Property Image */}
      <div className="w-12 h-12 rounded-lg overflow-hidden flex-shrink-0 bg-gray-200">
        {propertyImage ? (
          <img
            src={buildImageUrl(propertyImage)}
            alt="Property"
            className="w-full h-full object-cover"
          />
        ) : (
          <div className="w-full h-full flex items-center justify-center text-gray-400">
            <ChatBubbleLeftRightIcon className="w-6 h-6" />
          </div>
        )}
      </div>

      {/* Conversation Info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between">
          <h4 className="font-semibold text-sm text-gray-900 truncate">
            {conversation.otherParticipant?.name || "Unknown User"}
          </h4>
          {conversation.lastMessage?.createdAt && (
            <span className="text-[10px] text-gray-500">
              {formatDistanceToNow(new Date(conversation.lastMessage.createdAt), {
                addSuffix: false,
              })}
            </span>
          )}
        </div>
        <p className="text-xs text-gray-600 truncate">
          {conversation.property?.title || "Property"}
        </p>
        {conversation.lastMessage?.text && (
          <p className="text-xs text-gray-500 truncate mt-0.5">
            {conversation.lastMessage.text}
          </p>
        )}
      </div>

      {/* Unread Badge */}
      {conversation.myUnreadCount > 0 && (
        <div className="w-5 h-5 rounded-full bg-blue-600 text-white text-[10px] font-bold flex items-center justify-center flex-shrink-0">
          {conversation.myUnreadCount}
        </div>
      )}
    </div>
  );
};

// Main Chat Widget Component
const ChatWidget = () => {
  const {
    conversations,
    currentConversation,
    messages,
    loading,
    isChatOpen,
    isTyping,
    openChat,
    closeChat,
    sendMessage,
    emitTyping,
    emitStopTyping,
    isUserOnline,
    leaveConversation,
    reportMessage,
    sendVisitMessage,
  } = useChat();

  const { user: currentUser } = useAuth();

  const [messageText, setMessageText] = useState("");
  const [showConversations, setShowConversations] = useState(true);
  const [showActions, setShowActions] = useState(false);
  const [isVisitModalOpen, setIsVisitModalOpen] = useState(false);
  const messagesEndRef = useRef(null);
  const typingTimeoutRef = useRef(null);

  // Report State
  const [reportModalOpen, setReportModalOpen] = useState(false);
  const [selectedMessageForReport, setSelectedMessageForReport] = useState(null);
  const [reportReason, setReportReason] = useState("Asking for brokerage/commission");
  const [isReporting, setIsReporting] = useState(false);

  // Keep view (list vs messages) in sync with whether a
  // conversation is selected when the widget is opened.
  useEffect(() => {
    if (!isChatOpen) return;

    if (currentConversation) {
      setShowConversations(false);
    } else {
      setShowConversations(true);
    }
  }, [isChatOpen, currentConversation]);

  // Scroll to bottom on new messages
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  // Handle sending message
  const handleSendMessage = async (e) => {
    e.preventDefault();
    if (!messageText.trim() || !currentConversation) return;

    await sendMessage(currentConversation._id, messageText.trim());
    setMessageText("");
    emitStopTyping(currentConversation._id);
  };

  const handleOpenVisitModal = () => {
    if (!currentConversation || !currentConversation.property) {
      toast.error("Site visit is only available for property conversations.");
      return;
    }
    setShowActions(false);
    setIsVisitModalOpen(true);
  };

  const handleConfirmVisit = async ({ date, time }) => {
    if (!currentConversation) return;

    const propertyTitle = currentConversation.property?.title || "Property";
    const text = `Site visit requested for "${propertyTitle}" on ${date} at ${time}.`;

    const res = await sendVisitMessage(
      currentConversation._id,
      text,
      "visit_request"
    );

    if (res) {
      toast.success("Site visit request sent to owner.");
    } else {
      toast.error("Failed to send site visit request.");
    }
  };

  const handleAcceptVisit = async (message) => {
    if (!currentConversation) return;

    const text = `Site visit request accepted. ${message.text}`;

    const res = await sendVisitMessage(
      currentConversation._id,
      text,
      "visit_confirmation"
    );

    if (res) {
      toast.success("Visit accepted and buyer notified.");
    } else {
      toast.error("Failed to accept visit request.");
    }
  };

  // Handle typing
  const handleTyping = (e) => {
    setMessageText(e.target.value);

    if (currentConversation) {
      emitTyping(currentConversation._id);

      // Clear previous timeout
      if (typingTimeoutRef.current) {
        clearTimeout(typingTimeoutRef.current);
      }

      // Set timeout to stop typing
      typingTimeoutRef.current = setTimeout(() => {
        emitStopTyping(currentConversation._id);
      }, 2000);
    }
  };

  // Handle conversation click
  const handleConversationClick = (conversation) => {
    if (currentConversation) {
      leaveConversation(currentConversation._id);
    }
    openChat(conversation);
    setShowConversations(false);
  };

  // Handle back button
  const handleBack = () => {
    if (currentConversation) {
      leaveConversation(currentConversation._id);
    }
    setShowConversations(true);
    openChat(null);
  };

  // Handle Report Click
  const onReportClick = (message) => {
    setSelectedMessageForReport(message);
    setReportModalOpen(true);
  };

  // Submit Report
  const handleSubmitReport = async () => {
    if (!selectedMessageForReport) return;
    setIsReporting(true);
    const res = await reportMessage(selectedMessageForReport._id, reportReason);
    setIsReporting(false);

    if (res?.success) {
      toast.success("Message reported to admin.");
      setReportModalOpen(false);
      setReportReason("Asking for brokerage/commission");
      setSelectedMessageForReport(null);
    } else {
      toast.error(res?.message || "Failed to report message.");
    }
  };

  // Build image URL
  const buildImageUrl = (img) => {
    if (!img) return "";
    if (img.startsWith("http")) return img;
    if (img.startsWith("/uploads")) return `${API_BASE}${img}`;
    return `${API_BASE}/uploads/${img}`;
  };

  const isOwner = currentConversation?.isOwner;

  if (!isChatOpen) return null;

  return (
    <div className="fixed bottom-3 inset-x-2 sm:bottom-4 sm:right-4 sm:left-auto w-[calc(100%-1rem)] sm:w-[380px] h-[65vh] sm:h-[550px] bg-white rounded-2xl shadow-2xl border border-gray-200 flex flex-col overflow-hidden z-[12000]">
      {/* Header */}
      <div className="bg-gradient-to-r from-blue-600 to-blue-700 text-white px-4 py-3 flex items-center justify-between">
        {showConversations ? (
          <>
            <div className="flex items-center gap-2">
              <ChatBubbleLeftRightIcon className="w-6 h-6" />
              <h3 className="font-bold text-lg">Messages</h3>
            </div>
          </>
        ) : (
          <>
            <div className="flex items-center gap-3">
              <button
                onClick={handleBack}
                className="p-1 hover:bg-white/20 rounded-full transition"
              >
                <ArrowLeftIcon className="w-5 h-5" />
              </button>
              <div className="flex items-center gap-2">
                {currentConversation?.otherParticipant?.profileImage ? (
                  <img
                    src={buildImageUrl(currentConversation.otherParticipant.profileImage)}
                    alt=""
                    className="w-8 h-8 rounded-full object-cover"
                  />
                ) : (
                  <UserCircleIcon className="w-8 h-8" />
                )}
                <div>
                  <h4 className="font-semibold text-sm leading-tight">
                    {currentConversation?.otherParticipant?.name || "Chat"}
                  </h4>
                  <p className="text-[10px] text-blue-100">
                    {isUserOnline(currentConversation?.otherParticipant?._id)
                      ? "Online"
                      : "Offline"}
                  </p>
                </div>
              </div>
            </div>
          </>
        )}
        <button
          onClick={closeChat}
          className="p-1 hover:bg-white/20 rounded-full transition"
        >
          <XMarkIcon className="w-5 h-5" />
        </button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden relative">
        {showConversations ? (
          // Conversations List
          <div className="h-full overflow-y-auto">
            {conversations.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-gray-500 p-6">
                <ChatBubbleLeftRightIcon className="w-16 h-16 text-gray-300 mb-4" />
                <p className="text-center font-medium">No conversations yet</p>
                <p className="text-sm text-center mt-1">
                  Start chatting with property owners from property details page
                </p>
              </div>
            ) : (
              conversations.map((conv) => (
                <ConversationItem
                  key={conv._id}
                  conversation={conv}
                  isActive={currentConversation?._id === conv._id}
                  onClick={() => handleConversationClick(conv)}
                />
              ))
            )}
          </div>
        ) : (
          // Chat Messages
          <div className="h-full flex flex-col">
            {/* Property Info Bar */}
            {currentConversation?.property && (
              <div className="px-3 py-2 bg-gray-50 border-b border-gray-200 flex items-center gap-2">
                <div className="w-10 h-10 rounded-lg overflow-hidden bg-gray-200 flex-shrink-0">
                  {currentConversation.property.images?.[0] && (
                    <img
                      src={buildImageUrl(currentConversation.property.images[0])}
                      alt=""
                      className="w-full h-full object-cover"
                    />
                  )}
                </div>
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-semibold text-gray-900 truncate">
                    {currentConversation.property.title}
                  </p>
                  <p className="text-[10px] text-gray-500 truncate">
                    {currentConversation.property.address?.city || ""}
                  </p>
                </div>
              </div>
            )}

            {/* Messages */}
            <div className="flex-1 overflow-y-auto p-4">
              {loading ? (
                <div className="h-full flex items-center justify-center">
                  <div className="animate-spin w-8 h-8 border-3 border-blue-600 border-t-transparent rounded-full"></div>
                </div>
              ) : messages.length === 0 ? (
                <div className="h-full flex flex-col items-center justify-center text-gray-500">
                  <p className="text-sm">No messages yet</p>
                  <p className="text-xs mt-1">Send a message to start the conversation</p>
                </div>
              ) : (
                <>
                  {messages.map((msg) => (
                    <ChatMessage
                      key={msg._id}
                      message={msg}
                      isOwn={msg.sender?._id === currentUser._id}
                      onReport={onReportClick}
                      canAcceptVisit={Boolean(isOwner)}
                      onAcceptVisit={handleAcceptVisit}
                    />
                  ))}
                  {isTyping && isTyping.userId !== currentUser._id && (
                    <div className="flex items-center gap-2 text-gray-500 text-sm">
                      <div className="flex gap-1">
                        <span className="w-2 h-2 bg-gray-400 rounded-full animate-bounce"></span>
                        <span className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "0.1s" }}></span>
                        <span className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: "0.2s" }}></span>
                      </div>
                      <span className="text-xs">{isTyping.userName} is typing...</span>
                    </div>
                  )}
                  <div ref={messagesEndRef} />
                </>
              )}
            </div>

            {/* Message Input + actions */}
            <div className="relative">
              {/* Quick actions menu (buyer side) */}
              {!isOwner && (
                <div
                  className={`absolute bottom-16 left-3 z-10 transition-opacity ${showActions ? "opacity-100" : "opacity-0 pointer-events-none"
                    }`}
                >
                  <div className="bg-white border border-gray-200 rounded-xl shadow-lg py-2 w-48">
                    <button
                      type="button"
                      onClick={handleOpenVisitModal}
                      className="w-full text-left px-3 py-2 text-xs text-gray-800 hover:bg-gray-50"
                    >
                      Reserve a Site Visit
                    </button>
                  </div>
                </div>
              )}

              <form
                onSubmit={handleSendMessage}
                className="p-3 border-t border-gray-200 bg-gray-50"
              >
                <div className="flex items-center gap-2">
                  {!isOwner && (
                    <button
                      type="button"
                      onClick={() => setShowActions((prev) => !prev)}
                      className="ml-1 p-2 rounded-full border border-gray-300 bg-white text-gray-600 hover:bg-gray-100 hover:border-blue-400 transition"
                    >
                      <PlusIcon className="w-4 h-4" />
                    </button>
                  )}

                  <input
                    type="text"
                    value={messageText}
                    onChange={handleTyping}
                    placeholder="Type a message..."
                    className="flex-1 px-4 py-2.5 rounded-full border border-gray-300 focus:outline-none focus:border-blue-500 focus:ring-2 focus:ring-blue-100 text-sm"
                  />
                  <button
                    type="submit"
                    disabled={!messageText.trim()}
                    className="p-2.5 bg-blue-600 text-white rounded-full hover:bg-blue-700 transition disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <PaperAirplaneIcon className="w-5 h-5" />
                  </button>
                </div>
              </form>
            </div>
          </div>
        )}

        {/* Report Modal Overlay */}
        {reportModalOpen && (
          <div className="absolute inset-0 z-50 bg-black/50 backdrop-blur-sm flex items-center justify-center p-4">
            <div className="bg-white rounded-xl shadow-xl w-full max-w-xs p-4 animate-in fade-in zoom-in duration-200">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-bold text-gray-900 flex items-center gap-2">
                  <FlagIcon className="w-5 h-5 text-red-600" />
                  Report Message
                </h3>
                <button onClick={() => setReportModalOpen(false)} className="text-gray-400 hover:text-gray-600">
                  <XMarkIcon className="w-5 h-5" />
                </button>
              </div>

              <div className="mb-4">
                <p className="text-xs text-gray-500 mb-2 line-clamp-2 italic bg-gray-50 p-2 rounded">
                  "{selectedMessageForReport?.text}"
                </p>
                <label className="text-xs font-semibold text-gray-700 block mb-1">Reason</label>
                <select
                  value={reportReason}
                  onChange={(e) => setReportReason(e.target.value)}
                  className="w-full text-sm border border-gray-300 rounded-lg p-2 focus:ring-2 focus:ring-red-500 outline-none"
                >
                  <option value="Asking for brokerage/commission">Asking for brokerage/commission</option>
                  <option value="Listing info is incorrect">Listing information is incorrect</option>
                  <option value="Fake Property / Fraud">Fake Property / Fraud Suspected</option>
                  <option value="Unresponsive/Ghosting">Unresponsive / Ghosting</option>
                  <option value="Spam / Irrelevant Messages">Spam / Irrelevant Messages</option>
                  <option value="Abusive or Offensive Language">Abusive or Offensive Language</option>
                  <option value="Other">Other</option>
                </select>
              </div>

              <div className="flex gap-2">
                <button
                  onClick={() => setReportModalOpen(false)}
                  className="flex-1 py-2 text-sm font-medium text-gray-600 bg-gray-100 hover:bg-gray-200 rounded-lg transition"
                >
                  Cancel
                </button>
                <button
                  onClick={handleSubmitReport}
                  disabled={isReporting}
                  className="flex-1 py-2 text-sm font-medium text-white bg-red-600 hover:bg-red-700 rounded-lg transition disabled:opacity-50"
                >
                  {isReporting ? "Reporting..." : "Submit"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* Site Visit Modal (opened from + menu) */}
        {isVisitModalOpen && currentConversation?.property && (
          <VisitModal
            isOpen={isVisitModalOpen}
            onClose={() => setIsVisitModalOpen(false)}
            propertyTitle={currentConversation.property.title}
            onConfirm={handleConfirmVisit}
          />
        )}
      </div>
    </div>
  );
};

export default ChatWidget;
