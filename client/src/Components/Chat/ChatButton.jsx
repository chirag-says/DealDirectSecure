import React from "react";
import { useChat } from "../../context/ChatContext";
import { useAuth } from "../../context/AuthContext";
import { ChatBubbleLeftRightIcon } from "@heroicons/react/24/outline";

const ChatButton = () => {
  const { unreadCount, isChatOpen, openChat, fetchConversations } = useChat();
  const { isAuthenticated } = useAuth();

  if (!isAuthenticated) return null; // Don't show if not logged in

  const handleClick = () => {
    fetchConversations();
    openChat();
  };

  return (
    <button
      onClick={handleClick}
      className={`fixed bottom-6 right-6 w-14 h-14 rounded-full shadow-lg flex items-center justify-center transition-all z-40 ${isChatOpen
          ? "bg-gray-600 hover:bg-gray-700"
          : "bg-blue-600 hover:bg-blue-700 hover:scale-110"
        }`}
    >
      <ChatBubbleLeftRightIcon className="w-7 h-7 text-white" />

      {/* Unread Badge */}
      {unreadCount > 0 && !isChatOpen && (
        <span className="absolute -top-1 -right-1 w-6 h-6 bg-red-500 text-white text-xs font-bold rounded-full flex items-center justify-center animate-pulse">
          {unreadCount > 9 ? "9+" : unreadCount}
        </span>
      )}
    </button>
  );
};

export default ChatButton;
