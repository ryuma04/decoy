// Server-side route handler that forwards simulated client requests to the Divert Proxy (:8200).
// Adheres to root rule: browser only calls /api/..., server forwards to internal services.
export const dynamic = "force-dynamic";
export const runtime = "nodejs";

const proxyBase = process.env.DIVERT_PROXY_URL ?? "http://localhost:8200";
const coreBase = process.env.CORE_API_URL ?? "http://localhost:8090";

export async function GET(): Promise<Response> {
  const [proxyCheck, coreCheck] = await Promise.all([
    fetch(`${proxyBase}/`, { method: "HEAD", cache: "no-store" })
      .then((r) => r.ok || r.status < 500)
      .catch(() => false),
    fetch(`${coreBase}/healthz`, { method: "GET", cache: "no-store" })
      .then((r) => r.ok)
      .catch(() => false),
  ]);

  return Response.json({
    proxyOnline: proxyCheck,
    proxyUrl: proxyBase,
    coreOnline: coreCheck,
    coreUrl: coreBase,
  });
}

export async function POST(req: Request): Promise<Response> {
  try {
    const payload = await req.json();
    const { session, method = "GET", path = "/", body, headers = {} } = payload;

    if (!session || (session !== "attacker" && session !== "customer")) {
      return Response.json({ error: "session must be 'attacker' or 'customer'" }, { status: 400 });
    }

    // Determine cookie token for session isolation in the proxy
    const sessionToken = session === "attacker" ? "atk_live_session_1337" : "cust_live_session_9999";

    const targetUrl = new URL(path, proxyBase).toString();
    const reqHeaders: Record<string, string> = {
      Cookie: `_aet_v=${sessionToken}`,
      Accept: "text/html,application/json,*/*",
      "User-Agent":
        session === "attacker"
          ? "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AttackSim/1.0"
          : "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36",
      ...headers,
    };

    let fetchBody: string | undefined = undefined;
    if (body && (method === "POST" || method === "PUT" || method === "PATCH")) {
      if (typeof body === "string") {
        fetchBody = body;
      } else {
        fetchBody = JSON.stringify(body);
        if (!reqHeaders["Content-Type"]) {
          reqHeaders["Content-Type"] = "application/json";
        }
      }
    }

    const start = Date.now();
    const resp = await fetch(targetUrl, {
      method,
      headers: reqHeaders,
      body: fetchBody,
      redirect: "manual",
      cache: "no-store",
    }).catch((err) => {
      return {
        ok: false,
        status: 502,
        statusText: "Proxy Unreachable",
        error: err.message,
      };
    });

    const elapsed = Date.now() - start;

    if ("error" in resp) {
      return Response.json(
        {
          success: false,
          status: 502,
          statusText: "Bad Gateway",
          latencyMs: elapsed,
          bodySnippet: `Could not connect to Divert Proxy at ${proxyBase}. Ensure scripts/aetees-lab.sh and cmd/divert-proxy are running.`,
          upstream: "none",
        },
        { status: 502 }
      );
    }

    const respText = await resp.text();
    const respSnippet = respText.slice(0, 800);

    // Identify whether this was served by the clone honeypot or real shop
    let upstream: "clone" | "real" | "proxy_direct" = "real";
    if (
      respText.includes("<!-- DEBUG: Migration in progress") ||
      respText.includes("/backup/aetees_db_FINAL.sql.gz") ||
      respSnippet.includes("tok_aetees") ||
      resp.status === 503 && respSnippet.includes("We're receiving a lot of orders") ||
      resp.headers.get("x-divert-upstream") === "clone"
    ) {
      upstream = "clone";
    }

    return Response.json({
      success: resp.ok || resp.status < 400,
      status: resp.status,
      statusText: resp.statusText,
      latencyMs: elapsed,
      contentType: resp.headers.get("content-type") ?? "text/html",
      bodySnippet: respSnippet,
      upstream,
      targetUrl,
    });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : "Internal error";
    return Response.json({ error: message }, { status: 500 });
  }
}

