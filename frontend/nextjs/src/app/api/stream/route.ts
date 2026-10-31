// SSE pass-through to core. The generic /api rewrite buffers text/event-stream, so the live stream gets its
// own route handler that pipes the body through unbuffered (routes are matched before rewrites).
export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const core = process.env.CORE_API_URL ?? "http://localhost:8090";

export async function GET(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const upstream = await fetch(`${core}/v1/stream${url.search}`, {
    headers: { cookie: req.headers.get("cookie") ?? "", accept: "text/event-stream" },
    signal: req.signal,
    cache: "no-store",
  }).catch(() => null);
  if (!upstream) {
    return Response.json({ error: { code: "core_unreachable", message: "SOC core is not reachable" } }, { status: 502 });
  }
  if (!upstream.ok || !upstream.body) {
    return new Response(upstream.body, { status: upstream.status, headers: { "content-type": "application/json" } });
  }
  return new Response(upstream.body, {
    headers: {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "x-accel-buffering": "no",
    },
  });
}
