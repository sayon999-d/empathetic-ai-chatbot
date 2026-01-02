"use client";
import React, { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { MessageCircle, Loader } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

// Separate component that uses useSearchParams
function CallbackHandler() {
    const router = useRouter();
    const searchParams = useSearchParams();
    const [status, setStatus] = useState("processing");
    const [error, setError] = useState("");

    useEffect(() => {
        const exchangeCode = async () => {
            const code = searchParams.get("code");
            const errorParam = searchParams.get("error");

            if (errorParam) {
                setStatus("error");
                setError("Authentication was cancelled or failed.");
                setTimeout(() => router.push("/"), 3000);
                return;
            }

            if (!code) {
                setStatus("error");
                setError("No authentication code received.");
                setTimeout(() => router.push("/"), 3000);
                return;
            }

            try {
                const res = await fetch(`${API}/auth/exchange`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ code }),
                });

                const data = await res.json();

                if (data.error) {
                    setStatus("error");
                    setError(data.error);
                    setTimeout(() => router.push("/"), 3000);
                    return;
                }

                if (data.access_token) {
                    localStorage.setItem("access", data.access_token);
                    if (data.refresh_token) {
                        localStorage.setItem("refresh", data.refresh_token);
                    }
                    setStatus("success");
                    setTimeout(() => router.push("/"), 1500);
                }
            } catch (err) {
                setStatus("error");
                setError("Failed to complete authentication.");
                setTimeout(() => router.push("/"), 3000);
            }
        };

        exchangeCode();
    }, [searchParams, router]);

    return (
        <>
            {status === "processing" && (
                <>
                    <div className="flex justify-center mb-4">
                        <Loader className="w-8 h-8 animate-spin text-black" />
                    </div>
                    <h1 className="text-2xl font-bold mb-2">Completing Sign In...</h1>
                    <p className="text-gray-600">Please wait while we authenticate you.</p>
                </>
            )}

            {status === "success" && (
                <>
                    <h1 className="text-2xl font-bold mb-2 text-green-600">Success!</h1>
                    <p className="text-gray-600">Redirecting you to the chat...</p>
                </>
            )}

            {status === "error" && (
                <>
                    <h1 className="text-2xl font-bold mb-2 text-red-600">Authentication Failed</h1>
                    <p className="text-gray-600 mb-4">{error}</p>
                    <p className="text-sm text-gray-500">Redirecting to login...</p>
                </>
            )}
        </>
    );
}

// Loading fallback
function LoadingFallback() {
    return (
        <>
            <div className="flex justify-center mb-4">
                <Loader className="w-8 h-8 animate-spin text-black" />
            </div>
            <h1 className="text-2xl font-bold mb-2">Loading...</h1>
            <p className="text-gray-600">Please wait...</p>
        </>
    );
}

// Main page component with Suspense boundary
export default function AuthCallbackPage() {
    return (
        <div className="min-h-screen bg-black flex items-center justify-center p-4">
            <div className="bg-white rounded-3xl shadow-2xl w-full max-w-md p-8 text-center">
                <div className="flex justify-center mb-6">
                    <div className="bg-black p-4 rounded-2xl">
                        <MessageCircle className="w-8 h-8 text-white" />
                    </div>
                </div>

                <Suspense fallback={<LoadingFallback />}>
                    <CallbackHandler />
                </Suspense>
            </div>
        </div>
    );
}
