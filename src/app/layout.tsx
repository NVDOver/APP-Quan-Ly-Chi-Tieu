import type { Metadata } from "next";
import { Inter, Outfit } from "next/font/google";
import "./globals.css";
import "leaflet/dist/leaflet.css";
import { Providers } from "@/components/providers";

const inter = Inter({
  variable: "--font-sans",
  subsets: ["latin", "latin-ext"],
});

const outfit = Outfit({
  variable: "--font-heading",
  subsets: ["latin", "latin-ext"],
});

export const metadata: Metadata = {
  title: "SpendWise - Quản lý Chi tiêu Thông minh",
  description: "Giải pháp quản lý tài chính cá nhân toàn diện và hiệu quả.",
  manifest: "/manifest.json",
  appleWebApp: {
    capable: true,
    statusBarStyle: "black-translucent",
    title: "SpendWise",
    startupImage: "/icons/icon-512x512.png",
  },
  icons: [
    { rel: "icon", url: "/favicon-32.png", sizes: "32x32" },
    { rel: "apple-touch-icon", url: "/icons/apple-touch-icon.png", sizes: "180x180" },
  ],
};

export const viewport = {
  themeColor: "#10b981",
  width: "device-width",
  initialScale: 1,
  maximumScale: 1,
  userScalable: false,
  viewportFit: "cover",
};

import { Toaster } from "sonner";

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body
        className={`${inter.variable} ${outfit.variable} min-h-screen bg-background font-sans antialiased flex flex-col`}
      >
        <Providers>
          {children}
          <Toaster richColors position="top-right" />
        </Providers>
      </body>
    </html>
  );
}
