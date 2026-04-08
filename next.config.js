/* eslint-disable @typescript-eslint/no-require-imports */
const runtimeCaching = require("next-pwa/cache");

const withPWA = require("next-pwa")({
  dest: "public",
  disable: process.env.NODE_ENV !== "production",
  register: true,
  skipWaiting: true,
  buildExcludes: [/middleware-manifest\.json$/],
  cacheStartUrl: true,
  runtimeCaching,
  fallbacks: {
    document: "/offline",
    image: "/icons/icon-512x512.png",
  },
});

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  turbopack: {},
  allowedDevOrigins: [
    '192.168.100.179', 
    '8t7gsp-ip-42-112-70-41.tunnelmole.net',
    'localhost:3000'
  ],
};

module.exports = withPWA(nextConfig);
