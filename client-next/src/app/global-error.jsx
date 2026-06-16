'use client';

import * as Sentry from "@sentry/nextjs";
import { useEffect } from "react";


export default function GlobalError({ error, reset }) {
    useEffect(() => {
        // Log the error to Sentry
        Sentry.captureException(error);
    }, [error]);

    return (
        <html lang="en">
            <body>
                <div className="min-h-screen flex flex-col items-center justify-center bg-gray-50 px-4 text-center">
                    <h1 className="text-4xl font-bold text-gray-900 mb-4">Something went wrong!</h1>
                    <p className="text-gray-600 mb-8 max-w-md">
                        We apologize for the inconvenience. Our team has been notified of this issue.
                    </p>
                    <div className="flex gap-4">
                        <button
                            onClick={() => reset()}
                            className="px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition"
                        >
                            Try Again
                        </button>
                        <button
                            onClick={() => window.location.reload()}
                            className="px-6 py-3 bg-gray-200 text-gray-800 font-semibold rounded-lg hover:bg-gray-300 transition"
                        >
                            Reload Page
                        </button>
                    </div>
                    {/* Optional: Sentry User Feedback Widget could go here */}
                </div>
            </body>
        </html>
    );
}
