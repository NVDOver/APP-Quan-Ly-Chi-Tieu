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

module.exports = nextConfig;
