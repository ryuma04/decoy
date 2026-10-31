import type { NextConfig } from "next";

// Browser only ever calls /api/...; the Next server forwards to the core analyst API (11 §Backend access).
const core = process.env.CORE_API_URL ?? "http://localhost:8090";

const nextConfig: NextConfig = {
  output: "standalone",
  poweredByHeader: false,
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${core}/v1/:path*` }];
  },
};

export default nextConfig;
