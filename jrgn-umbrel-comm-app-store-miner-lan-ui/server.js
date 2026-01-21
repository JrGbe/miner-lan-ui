import express from "express";
import fetch from "node-fetch";
import dns from "dns/promises";
import net from "net";

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.static("public", { maxAge: 0 }));

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some(n => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = parts;
  if (a === 10) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;
  if (a === 169 && b === 254) return true;
  if (a === 127) return true;
  return false;
}

async function validateLanUrl(raw) {
  if (!/^https?:\/\//i.test(raw)) raw = "http://" + raw;
  const u = new URL(raw);

  // Allow http + https (your Avalon is http; https is optional)
  if (u.protocol !== "http:" && u.protocol !== "https:") {
    throw new Error("Only http:// and https:// are allowed");
  }

  const host = u.hostname.toLowerCase();

  if (net.isIP(host) === 4) {
    if (!isPrivateIPv4(host)) throw new Error("Only LAN/private IPv4 allowed");
    return u;
  }

  // allow .local but ensure it resolves to private IP
  if (!host.endsWith(".local")) throw new Error("Only LAN hosts allowed (.local or private IPv4)");
  const res = await dns.lookup(host, { family: 4 });
  if (!res?.address || !isPrivateIPv4(res.address)) throw new Error(".local must resolve to private IPv4");

  return u;
}

function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Buffer.from(s, "base64").toString("utf8");
}

function rewriteHtmlForProxy(html, prefix) {
  // Rewrite root-relative URLs so /css/app.css becomes /browse/<id>/css/app.css
  // Covers href/src/action/srcset and CSS url(/...)
  return html
    .replace(/(href|src|action)=["']\/(?!\/)/gi, `$1="${prefix}/`)
    .replace(/srcset=["']\/(?!\/)/gi, `srcset="${prefix}/`)
    .replace(/url\(\s*\/(?!\/)/gi, `url(${prefix}/`);
}

// Proxy everything under /browse/<base64url(target)>/*
app.use(/^\/browse\/([^\/]+)(\/.*)?$/i, async (req, res) => {
  try {
    const id = req.params[0] || req.path.split("/")[2];
    const restPath = req.params[1] || req.originalUrl.replace(/^\/browse\/[^\/]+/i, "") || "/";

    const targetStr = b64urlDecode(id);
    const base = await validateLanUrl(targetStr);

    const upstreamUrl = new URL(base.toString());
    upstreamUrl.pathname = restPath;
    upstreamUrl.search = req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "";

    const upstream = await fetch(upstreamUrl.toString(), {
      method: req.method,
      redirect: "manual",
      headers: {
        // forward a few headers safely
        "user-agent": req.get("user-agent") || "Umbrel-LAN-Proxy/1.0",
        "accept": req.get("accept") || "*/*"
      }
    });

    // Handle redirects: rewrite Location back through proxy if it points to same host
    const loc = upstream.headers.get("location");
    if (loc && (upstream.status === 301 || upstream.status === 302 || upstream.status === 303 || upstream.status === 307 || upstream.status === 308)) {
      try {
        const locUrl = new URL(loc, upstreamUrl);
        // If redirect stays on the same origin, keep it proxied
        if (locUrl.host === upstreamUrl.host) {
          const prefix = `/browse/${id}`;
          const proxiedLoc = prefix + locUrl.pathname + (locUrl.search || "");
          res.setHeader("location", proxiedLoc);
        } else {
          res.setHeader("location", loc); // external redirect as-is
        }
      } catch {
        res.setHeader("location", loc);
      }
      res.status(upstream.status).end();
      return;
    }

    // Copy content-type
    const ct = upstream.headers.get("content-type") || "application/octet-stream";
    res.status(upstream.status);
    res.setHeader("content-type", ct);

    // If HTML, rewrite links so assets load through /browse/<id>/...
    if (ct.includes("text/html")) {
      const text = await upstream.text();
      const prefix = `/browse/${id}`;
      res.send(rewriteHtmlForProxy(text, prefix));
      return;
    }

    // Stream everything else
    if (upstream.body) upstream.body.pipe(res);
    else res.end();
  } catch (e) {
    res.status(400).send(String(e?.message || e));
  }
});

app.listen(PORT, () => console.log(`LAN UI listening on ${PORT}`));
