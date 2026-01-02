"use client";
import React, { useState, useEffect, useRef } from "react";
import {
  MessageCircle,
  Send,
  User,
  Lock,
  LogOut,
  Eye,
  EyeOff,
} from "lucide-react";

// Use environment variables with fallbacks for development
const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";
const WS = process.env.NEXT_PUBLIC_WS_URL || "ws://localhost:8000/ws/chat";

export default function LoginChatApp() {
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [userId, setUserId] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState("");

  const [messages, setMessages] = useState([]);
  const [inputMessage, setInputMessage] = useState("");
  const [isLoading, setIsLoading] = useState(false);

  /* ---------------- SESSION RESTORE + OAUTH CALLBACK ---------------- */
  useEffect(() => {
    const handleAuth = async () => {
      const params = new URLSearchParams(window.location.search);

      // Handle OAuth error
      const oauthError = params.get("error");
      if (oauthError) {
        setError("Google sign-in failed. Please try again.");
        window.history.replaceState({}, document.title, "/");
        return;
      }

      // Handle OAuth code exchange (more secure than tokens in URL)
      const oauthCode = params.get("code");
      if (oauthCode) {
        try {
          const res = await fetch(`${API}/auth/exchange`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ code: oauthCode }),
          });

          const data = await res.json();

          if (data.error) {
            setError("Authentication failed: " + data.error);
          } else if (data.access_token) {
            localStorage.setItem("access", data.access_token);
            if (data.refresh_token) {
              localStorage.setItem("refresh", data.refresh_token);
            }
            setIsLoggedIn(true);
            setMessages([
              { text: "Welcome! You've signed in with Google. How can I assist you today?", sender: "bot" },
            ]);
          }
        } catch (err) {
          setError("Failed to complete authentication.");
        }

        // Clean URL
        window.history.replaceState({}, document.title, "/");
        return;
      }

      // Check for existing session
      const token = localStorage.getItem("access");
      if (token) {
        setIsLoggedIn(true);
        setMessages([
          { text: "Hello! How can I assist you today?", sender: "bot" },
        ]);
      }
    };

    handleAuth();
  }, []);

  /* ---------------- TOKEN REFRESH ---------------- */
  const refreshAccessToken = async () => {
    const refreshToken = localStorage.getItem("refresh");
    if (!refreshToken) return false;

    try {
      const res = await fetch(`${API}/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: refreshToken }),
      });

      const data = await res.json();
      if (data.access_token) {
        localStorage.setItem("access", data.access_token);
        return true;
      }
    } catch (err) {
      console.error("Token refresh failed:", err);
    }

    return false;
  };

  /* ---------------- LOGIN ---------------- */
  const handleLogin = async () => {
    setError("");

    if (!userId.trim() || !password) {
      setError("Please enter username and password");
      return;
    }

    try {
      const res = await fetch(`${API}/login`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: userId.trim(), password }),
      });

      const data = await res.json();

      if (data.error) {
        setError(data.error);
        return;
      }

      if (data.access_token) {
        localStorage.setItem("access", data.access_token);
        localStorage.setItem("refresh", data.refresh_token || "");
        setIsLoggedIn(true);
        setMessages([
          { text: "Hello! How can I assist you today?", sender: "bot" },
        ]);
      }
    } catch (err) {
      setError("Connection failed. Please try again.");
    }
  };

  /* ---------------- GOOGLE AUTH ---------------- */
  const handleGoogleSignup = () => {
    window.location.href = `${API}/auth/google`;
  };

  /* ---------------- LOGOUT ---------------- */
  const handleLogout = () => {
    localStorage.removeItem("access");
    localStorage.removeItem("refresh");
    setIsLoggedIn(false);
    setUserId("");
    setPassword("");
    setMessages([]);
    setError("");
  };

  /* ---------------- SEND MESSAGE (REST API) ---------------- */
  const handleSendMessage = async () => {
    if (!inputMessage.trim() || isLoading) return;

    const userMessage = inputMessage.trim();

    // Client-side validation
    if (userMessage.length > 5000) {
      setMessages((prev) => [
        ...prev,
        { text: "Message is too long. Please keep it under 5000 characters.", sender: "bot" },
      ]);
      return;
    }

    setMessages((prev) => [...prev, { text: userMessage, sender: "user" }]);
    setInputMessage("");
    setIsLoading(true);

    try {
      const res = await fetch(`${API}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          token: localStorage.getItem("access"),
          message: userMessage,
        }),
      });

      const data = await res.json();

      if (data.error === "Unauthorized") {
        // Try to refresh token
        const refreshed = await refreshAccessToken();
        if (refreshed) {
          // Retry the request
          const retryRes = await fetch(`${API}/chat`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              token: localStorage.getItem("access"),
              message: userMessage,
            }),
          });
          const retryData = await retryRes.json();

          if (retryData.error) {
            setMessages((prev) => [
              ...prev,
              { text: "Error: " + retryData.error, sender: "bot" },
            ]);
          } else {
            setMessages((prev) => [
              ...prev,
              { text: retryData.response, sender: "bot" },
            ]);
          }
        } else {
          // Refresh failed, logout
          handleLogout();
          setError("Session expired. Please log in again.");
        }
      } else if (data.error) {
        setMessages((prev) => [
          ...prev,
          { text: "Error: " + data.error, sender: "bot" },
        ]);
      } else {
        setMessages((prev) => [
          ...prev,
          { text: data.response, sender: "bot" },
        ]);
      }
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        { text: "Connection error. Please try again.", sender: "bot" },
      ]);
    }

    setIsLoading(false);
  };

  /* ===================== LOGIN UI ===================== */
  if (!isLoggedIn) {
    return (
      <div className="min-h-screen bg-black flex items-center justify-center p-4">
        <div className="bg-white rounded-3xl shadow-2xl w-full max-w-md p-8">
          <div className="flex justify-center mb-6">
            <div className="bg-black p-4 rounded-2xl">
              <MessageCircle className="w-8 h-8 text-white" />
            </div>
          </div>

          <h1 className="text-3xl font-bold text-center mb-2">Welcome Back</h1>
          <p className="text-center text-gray-600 mb-8">
            Login to continue chatting
          </p>

          {error && (
            <div className="mb-4 p-3 bg-red-100 border border-red-300 rounded-xl text-red-600 text-sm text-center">
              {error}
            </div>
          )}

          <div className="space-y-5">
            <div>
              <label className="block mb-2">User ID</label>
              <div className="relative">
                <User className="absolute left-3 top-3 text-gray-400" />
                <input
                  value={userId}
                  onChange={(e) => setUserId(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleLogin()}
                  className="w-full pl-10 py-3 border rounded-xl"
                  placeholder="Enter username"
                  maxLength={30}
                />
              </div>
            </div>

            <div>
              <label className="block mb-2">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 text-gray-400" />
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  onKeyDown={(e) => e.key === "Enter" && handleLogin()}
                  className="w-full pl-10 pr-12 py-3 border rounded-xl"
                  placeholder="Enter password"
                  maxLength={128}
                />
                <button
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3"
                  type="button"
                >
                  {showPassword ? <EyeOff /> : <Eye />}
                </button>
              </div>
            </div>

            <button
              onClick={handleLogin}
              className="w-full bg-black text-white py-3 rounded-xl hover:bg-gray-800 transition-colors"
            >
              Login
            </button>
          </div>

          <div className="my-6 text-center text-gray-500">OR</div>

          <button
            onClick={handleGoogleSignup}
            className="w-full border py-3 rounded-xl hover:bg-gray-50 transition-colors"
          >
            Sign in with Google
          </button>

          <p className="text-center mt-4 text-sm">
            Don't have an account?{" "}
            <a
              href="/signup"
              className="font-semibold underline cursor-pointer"
            >
              Sign up
            </a>
          </p>
        </div>
      </div>
    );
  }

  /* ===================== CHAT UI ===================== */
  return (
    <div className="min-h-screen bg-black flex flex-col">
      <div className="bg-white p-4 flex justify-between items-center">
        <h1 className="font-bold">Empathetic AI Chatbot</h1>
        <button onClick={handleLogout} className="flex gap-2 hover:text-red-600 transition-colors">
          <LogOut /> Logout
        </button>
      </div>

      <div className="flex-1 p-4 overflow-y-auto space-y-4 bg-white">
        {messages.map((m, i) => (
          <div
            key={i}
            className={`flex ${m.sender === "user" ? "justify-end" : "justify-start"
              }`}
          >
            <div
              className={`px-4 py-2 rounded-xl max-w-[80%] ${m.sender === "user"
                ? "bg-black text-white"
                : "bg-gray-200"
                }`}
            >
              {m.text}
            </div>
          </div>
        ))}
        {isLoading && (
          <div className="flex justify-start">
            <div className="px-4 py-2 rounded-xl bg-gray-200">
              <span className="animate-pulse">Thinking...</span>
            </div>
          </div>
        )}
      </div>

      <div className="p-4 bg-gray-100 flex gap-3">
        <input
          value={inputMessage}
          onChange={(e) => setInputMessage(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSendMessage()}
          className="flex-1 px-4 py-3 border rounded-full"
          placeholder="Type your message..."
          maxLength={5000}
        />
        <button
          onClick={handleSendMessage}
          disabled={isLoading}
          className="bg-black text-white p-3 rounded-xl disabled:opacity-50 hover:bg-gray-800 transition-colors"
        >
          <Send />
        </button>
      </div>
    </div>
  );
}