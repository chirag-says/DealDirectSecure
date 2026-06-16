import { Inter } from "next/font/google";
import "./globals.css";
import ClientLayout from "./ClientLayout";

const inter = Inter({
  variable: "--font-inter",
  subsets: ["latin"],
  display: "swap",
});

export const metadata = {
  metadataBase: new URL('https://dealdirect.in'),
  title: {
    default: "DealDirect — Buy & Sell Properties Without Middlemen",
    template: "%s | DealDirect",
  },
  description:
    "DealDirect is India's #1 platform for buying, selling, and renting properties directly from owners — no brokerage, no middlemen. Browse apartments, villas, plots, and commercial spaces across Mumbai, Delhi, Bangalore, and more.",
  keywords: [
    "real estate",
    "property",
    "buy property",
    "sell property",
    "rent property",
    "no brokerage",
    "direct from owner",
    "apartments",
    "villas",
    "flats",
    "India",
    "DealDirect",
  ],
  openGraph: {
    type: "website",
    locale: "en_IN",
    url: "https://dealdirect.in",
    siteName: "DealDirect",
    title: "DealDirect — Buy & Sell Properties Without Middlemen",
    description:
      "India's #1 platform for direct property deals. No brokerage. No middlemen.",
  },
  twitter: {
    card: "summary_large_image",
    title: "DealDirect — Buy & Sell Properties Without Middlemen",
    description:
      "India's #1 platform for direct property deals. No brokerage. No middlemen.",
  },
  robots: {
    index: true,
    follow: true,
  },
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        {/* DNS prefetch for Cloudinary CDN (all property/blog images) */}
        <link rel="dns-prefetch" href="https://res.cloudinary.com" />
        <link rel="preconnect" href="https://res.cloudinary.com" crossOrigin="anonymous" />
        {/* Dark mode anti-flash: apply theme class before React hydrates */}
        <script
          dangerouslySetInnerHTML={{
            __html: `(function(){var t=localStorage.getItem('dd-theme');if(t==='dark'||(t==='system'||!t)&&window.matchMedia('(prefers-color-scheme: dark)').matches){document.documentElement.classList.add('dark');}})();`,
          }}
        />
      </head>
      <body className={`${inter.variable} antialiased`}>
        <ClientLayout>{children}</ClientLayout>
      </body>
    </html>
  );
}
