import express from "express";
import fetch from "node-fetch";
import os from "os";
import net from "net";

const app = express();
const PORT = process.env.PORT || 8080;

app.use(express.static("public", { maxAge: 0 }));

// ---------- IPv4 helpers ----------
function ipToInt(ip) {
  return ip.split(".").reduce((acc, oct) => (acc << 8) + Number(oct), 0) >>> 0;
}
function intToIp(n) {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}
function maskToPrefix(mask) {
  const m = ipToInt(mask);
  // count 1 bits
  let cnt = 0;
  for (let i = 31; i >= 0; i--) cnt += (m >>> i) & 1;
  return cnt;
}
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

function getPrimaryPrivateInterface() {
  const ifaces = os.networkInterfaces();
  for (const name of Object.keys(ifaces)) {
    for (const info of ifaces[name] || []) {
      if (info.family === "IPv4" && !info.internal && isPrivateIPv4(info.address)) {
        return { name, address: info.address, netmask: info.netmask };
      }
    }
  }
  // fallback: allow internal if that’s all we have (rare)
  for (const name of Object.keys(ifaces)) {
    for (const info of ifaces[name] || []) {
      if (info.family === "IPv4" && isPrivateIPv4(info.address)) {
        return { name, address: info.address, netmask: info.netmask };
      }
    }
  }
  return null;
}

function buildSubnetIps(address, netmask, maxHosts = 1024) {
  const ip = ipToInt(address);
  const mask = ipToInt(netmask);
  const network = ip & mask;
  const broadcast = network | (~mask >>> 0);

  // exclude network & broadcast
  const start = network + 1;
  const end = broadcast - 1;

  const total = end >= start ? (end - start + 1) : 0;
  const limit = Math.min(total, maxHosts);

  const ips = [];
  for (let i = 0; i < limit; i++) ips.push(intToIp(start + i));
  return { ips, total };
}

// ---------- HTTP probe ----------
async function fetchWithTimeout(url, ms) {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), ms);
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: { "user-agent": "Umbrel-Miner-Scanner/1.0" }
    });
    const ct = res.headers.get("content-type") || "";
    // read some body for signature matching
    const text = ct.includes("text") || ct.includes("html") ? await res.text() : "";
    return { ok: true, status: res.status, ct, text };
  } catch (e) {
    return { ok: false, error: e?.name || String(e) };
  } finally {
    clearTimeout(t);
  }
}

function detectMiner(html) {
  const h = (html || "").toLowerCase();
  if (h.includes("avalon device")) return "Avalon";
  if (h.includes("antminer") || h.includes("bitmain")) return "Antminer";
  if (h.includes("whatsminer")) return "WhatsMiner";
  if (h.includes("braiins") || h.includes("bos")) return "Braiins OS";
  return null;
}

// Simple concurrency limiter
async function mapLimit(items, limit, fn) {
  const results = [];
  let idx = 0;
  const workers = Array.from({ length: limit }, async () => {
    while (idx < items.length) {
      const i = idx++;
      results[i] = await fn(items[i]);
    }
  });
  await Promise.all(workers);
  return results;
}

// ---------- SCAN ENDPOINT ----------
app.get("/scan", async (req, res) => {
  const iface = getPrimaryPrivateInterface();
  if (!iface) return res.status(400).json({ error: "No private IPv4 interface found." });

  const { ips, total } = buildSubnetIps(iface.address, iface.netmask, 1024);

  // common miner UI ports
  const ports = [80, 8080];

  // probe each IP/port quickly
  const timeoutMs = 800;
  const concurrency = 60;

  const checks = [];
  for (const ip of ips) {
    for (const p of ports) checks.push({ ip, port: p });
  }

  const out = await mapLimit(checks, concurrency, async ({ ip, port }) => {
    const url = `http://${ip}:${port}/`;
    const r = await fetchWithTimeout(url, timeoutMs);
    if (!r.ok) return null;

    // Many devices return 404 to HEAD but 200 to GET; we use GET.
    const vendor = detectMiner(r.text);
    if (!vendor) return null;

    return {
      ip,
      port,
      vendor,
      url: port === 80 ? `http://${ip}/` : `http://${ip}:${port}/`
    };
  });

  // de-dup per IP+port
  const found = out.filter(Boolean);

  res.json({
    interface: iface,
    scannedHosts: Math.min(total, 1024),
    found
  });
});

app.listen(PORT, () => console.log(`Miner LAN UI listening on ${PORT}`));
