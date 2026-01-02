"use client";
import React, { useState } from "react";
import { useRouter } from "next/navigation";
import {
    MessageCircle,
    User,
    Lock,
    Eye,
    EyeOff,
} from "lucide-react";

// Use environment variables with fallbacks for development
const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export default function SignupPage() {
    const router = useRouter();
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const [showPassword, setShowPassword] = useState(false);
    const [showConfirmPassword, setShowConfirmPassword] = useState(false);
    const [error, setError] = useState("");
    const [loading, setLoading] = useState(false);

    const validateForm = () => {
        // Username validation
        if (!username || username.trim().length < 3) {
            setError("Username must be at least 3 characters");
            return false;
        }
        if (username.length > 30) {
            setError("Username must be less than 30 characters");
            return false;
        }
        if (!/^[a-zA-Z0-9_]+$/.test(username)) {
            setError("Username can only contain letters, numbers, and underscores");
            return false;
        }

        // Password validation
        if (!password || password.length < 8) {
            setError("Password must be at least 8 characters");
            return false;
        }
        if (password.length > 128) {
            setError("Password must be less than 128 characters");
            return false;
        }

        // Confirm password
        if (password !== confirmPassword) {
            setError("Passwords do not match");
            return false;
        }

        return true;
    };

    const handleSignup = async (e) => {
        e.preventDefault();
        setError("");

        if (!validateForm()) {
            return;
        }

        setLoading(true);

        try {
            const res = await fetch(`${API}/signup`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    username: username.trim(),
                    password
                }),
            });

            const data = await res.json();

            if (data.error) {
                setError(data.error);
                setLoading(false);
                return;
            }

            if (data.access_token) {
                localStorage.setItem("access", data.access_token);
                localStorage.setItem("refresh", data.refresh_token || "");
                router.push("/");
            }
        } catch (err) {
            setError("Something went wrong. Please try again.");
        }

        setLoading(false);
    };

    const handleGoogleSignup = () => {
        window.location.href = `${API}/auth/google`;
    };

    return (
        <div className="min-h-screen bg-black flex items-center justify-center p-4">
            <div className="bg-white rounded-3xl shadow-2xl w-full max-w-md p-8">
                <div className="flex justify-center mb-6">
                    <div className="bg-black p-4 rounded-2xl">
                        <MessageCircle className="w-8 h-8 text-white" />
                    </div>
                </div>

                <h1 className="text-3xl font-bold text-center mb-2">Create Account</h1>
                <p className="text-center text-gray-600 mb-8">
                    Sign up to start chatting
                </p>

                {error && (
                    <div className="mb-4 p-3 bg-red-100 border border-red-300 rounded-xl text-red-600 text-sm text-center">
                        {error}
                    </div>
                )}

                <form onSubmit={handleSignup} className="space-y-5">
                    {/* Username */}
                    <div>
                        <label className="block mb-2">Username</label>
                        <div className="relative">
                            <User className="absolute left-3 top-3 text-gray-400" />
                            <input
                                type="text"
                                value={username}
                                onChange={(e) => setUsername(e.target.value)}
                                className="w-full pl-10 py-3 border rounded-xl"
                                placeholder="Choose a username"
                                maxLength={30}
                            />
                        </div>
                        <p className="text-xs text-gray-500 mt-1">
                            3-30 characters, letters, numbers, and underscores only
                        </p>
                    </div>

                    {/* Password */}
                    <div>
                        <label className="block mb-2">Password</label>
                        <div className="relative">
                            <Lock className="absolute left-3 top-3 text-gray-400" />
                            <input
                                type={showPassword ? "text" : "password"}
                                value={password}
                                onChange={(e) => setPassword(e.target.value)}
                                className="w-full pl-10 pr-12 py-3 border rounded-xl"
                                placeholder="Create a password"
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
                        <p className="text-xs text-gray-500 mt-1">
                            Minimum 8 characters
                        </p>
                    </div>

                    {/* Confirm Password */}
                    <div>
                        <label className="block mb-2">Confirm Password</label>
                        <div className="relative">
                            <Lock className="absolute left-3 top-3 text-gray-400" />
                            <input
                                type={showConfirmPassword ? "text" : "password"}
                                value={confirmPassword}
                                onChange={(e) => setConfirmPassword(e.target.value)}
                                className="w-full pl-10 pr-12 py-3 border rounded-xl"
                                placeholder="Confirm your password"
                                maxLength={128}
                            />
                            <button
                                onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                                className="absolute right-3 top-3"
                                type="button"
                            >
                                {showConfirmPassword ? <EyeOff /> : <Eye />}
                            </button>
                        </div>
                    </div>

                    {/* Submit Button */}
                    <button
                        type="submit"
                        disabled={loading}
                        className="w-full bg-black text-white py-3 rounded-xl disabled:opacity-50 hover:bg-gray-800 transition-colors"
                    >
                        {loading ? "Creating account..." : "Sign Up"}
                    </button>
                </form>

                <div className="my-6 text-center text-gray-500">OR</div>

                <button
                    onClick={handleGoogleSignup}
                    className="w-full border py-3 rounded-xl hover:bg-gray-50 transition-colors"
                >
                    Sign up with Google
                </button>

                <p className="text-center mt-4 text-sm">
                    Already have an account?{" "}
                    <a
                        href="/"
                        className="font-semibold underline cursor-pointer"
                    >
                        Sign in
                    </a>
                </p>
            </div>
        </div>
    );
}