import express from "express";
import fetch from "node-fetch";
import dns from "dns/promises";
import net from "net";

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.static("public", { maxAge: 0 }));

function isPrivateIPv4(ip) {
  // block localhost
  if (ip.startsWith("127.")) return false;

  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return false;

  const [a, b] = parts;

  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;

  return false;
}

async function validateLanHttpUrl(raw) {
  let u;
  try {
    // enforce http only (no https)
    if (/^https:\/\//i.test(raw)) throw new Error("HTTPS not allowed");
    if (!/^https?:\/\//i.test(raw)) raw = "http://" + raw;

    u = new URL(raw);
  } catch {
    throw new Error("Invalid URL");
  }

  if (u.protocol !== "http:") throw new Error("Only http:// is allowed");

  const host = u.hostname.toLowerCase();

  // If host is an IPv4 address
  if (net.isIP(host) === 4) {
    if (!isPrivateIPv4(host)) throw new Error("Only private LAN IPv4 allowed");
    return u;
  }

  // Allow .local but verify it resolves to a private IP
  if (!host.endsWith(".local")) {
    throw new Error("Only LAN hosts allowed (.local or private IPv4)");
  }

  const res = await dns.lookup(host, { family: 4 });
  if (!res?.address || !isPrivateIPv4(res.address)) {
    throw new Error(".local did not resolve to a private IPv4");
  }

  return u;
}

app.get("/proxy", async (req, res) => {
  try {
    const targetRaw = req.query.u;
    if (!targetRaw) return res.status(400).send("Missing u=");

    const target = await validateLanHttpUrl(String(targetRaw));

    // Forward method + headers safely (basic)
    const upstream = await fetch(target.toString(), {
      method: "GET",
      redirect: "follow",
      headers: {
        // Keep it simple; many UIs behave better with a browser UA
        "user-agent": "Umbrel-LAN-Proxy/1.0"
      }
    });

    // Copy status + content-type
    res.status(upstream.status);
    const ct = upstream.headers.get("content-type") || "application/octet-stream";
    res.setHeader("content-type", ct);

    // Stream body
    if (upstream.body) upstream.body.pipe(res);
    else res.end();
  } catch (e) {
    res.status(400).send(String(e?.message || e));
  }
});

app.listen(PORT, () => console.log(`LAN UI listening on ${PORT}`));
