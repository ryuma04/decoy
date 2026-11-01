// Lightweight lab shop upstream emulator for local development and split-screen demo.
// Provides both real shop (:3100) and honeypot clone (:3101) upstreams with zero external dependencies.
import http from "node:http";

function createShop(port, isClone) {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, `http://127.0.0.1:${port}`);
    const path = url.pathname;
    let body = "";

    req.on("data", (chunk) => { body += chunk; });
    req.on("end", () => {
      // CORS & JSON helpers
      res.setHeader("X-Shop-Instance", isClone ? "clone-honeypot" : "real-production");

      if (path === "/" || path === "/menu") {
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        const comment = isClone ? "\n<!-- DEBUG: Migration in progress. Remove /.env.bak and /backup/ before production release. -->\n" : "";
        res.end(`<!DOCTYPE html>
<html>
<head><title>Aetees Bakehouse - Artisanal Bakery</title></head>
<body>
  <h1>Aetees Bakehouse ${isClone ? "(Synthetic Lab Clone)" : "(Production)"}</h1>
  <p>Fresh artisanal cakes, sourdoughs, and cookies.</p>
  <ul>
    <li>Chocolate Truffle Cake - Rs. 650</li>
    <li>Blueberry Cheesecake - Rs. 750</li>
  </ul>${comment}
</body>
</html>`);
        return;
      }

      if (path === "/api/cart") {
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({
          success: true,
          cartId: isClone ? "cart_clone_synth_99" : "cart_live_real_42",
          items: [{ id: 1, name: "Chocolate Truffle Cake", qty: 2 }]
        }));
        return;
      }

      if (path === "/api/checkout") {
        res.setHeader("Content-Type", "application/json");
        if (isClone) {
          // Clone shop or held write
          res.statusCode = 200;
          res.end(JSON.stringify({
            success: true,
            orderId: "ORD-SYNTH-9941",
            message: "Synthetic order recorded in honeypot sandbox"
          }));
        } else {
          // Real production shop
          res.statusCode = 200;
          res.end(JSON.stringify({
            success: true,
            orderId: "ORD-LIVE-7842",
            message: "Order placed successfully on production database"
          }));
        }
        return;
      }

      if (path === "/api/contact") {
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({
          success: true,
          message: "Thank you for contacting Aetees Bakehouse. We will respond shortly."
        }));
        return;
      }

      if (path === "/api/admin/login") {
        res.setHeader("Content-Type", "application/json");
        if (isClone) {
          res.end(JSON.stringify({
            success: true,
            token: "tok_synth_admin_session",
            role: "admin",
            message: "Welcome to Aetees Admin (Synthetic Sandbox)"
          }));
        } else {
          res.statusCode = 401;
          res.end(JSON.stringify({
            success: false,
            error: "Invalid credentials"
          }));
        }
        return;
      }

      if (path === "/api/admin/export") {
        res.setHeader("Content-Type", "application/json");
        res.end(JSON.stringify({
          job_id: "exp_job_974",
          progress: 97.4,
          status: "generating_csv",
          message: "Exporting synthetic customer records..."
        }));
        return;
      }

      // Default 404
      res.statusCode = 404;
      res.setHeader("Content-Type", "text/html");
      res.end("<h1>404 Not Found - Aetees Bakehouse</h1>");
    });
  });

  server.listen(port, "127.0.0.1", () => {
    console.log(`[lab-shop] ${isClone ? "Clone Honeypot" : "Real Shop"} listening on http://127.0.0.1:${port}`);
  });
  return server;
}

createShop(3100, false);
createShop(3101, true);
