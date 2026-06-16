import Link from 'next/link';

export default function NotFound() {
    return (
        <div className="min-h-screen flex flex-col items-center justify-center bg-gradient-to-b from-slate-50 to-white px-4">
            <div className="text-center max-w-md">
                <h1 className="text-8xl font-extrabold text-red-600 mb-4">404</h1>
                <h2 className="text-2xl font-bold text-slate-800 mb-3">Page Not Found</h2>
                <p className="text-slate-500 mb-8">
                    The page you're looking for doesn't exist or has been moved.
                </p>
                <div className="flex flex-col sm:flex-row gap-3 justify-center">
                    <Link
                        href="/"
                        className="inline-flex items-center justify-center px-6 py-3 bg-red-600 text-white font-semibold rounded-xl hover:bg-red-700 transition shadow-lg"
                    >
                        Go Home
                    </Link>
                    <Link
                        href="/properties"
                        className="inline-flex items-center justify-center px-6 py-3 bg-white text-slate-700 font-semibold rounded-xl border border-slate-200 hover:bg-slate-50 transition"
                    >
                        Browse Properties
                    </Link>
                </div>
            </div>
        </div>
    );
}
