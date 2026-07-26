#!/usr/bin/env node
/**
 * JIAOZI status sentinel.
 * Runs on GitHub Actions as an independent third-party vantage point
 * (isolated from JIAOZI production infrastructure in CN/SG).
 *
 * Probes public endpoints, cryptographically verifies signed status
 * credentials (jiaozi.status.v1), tracks serial monotonicity, then renders
 * a static status page into site/ and appends machine-readable history
 * into data/.
 */

import { verify as edVerify } from "node:crypto";
import { appendFileSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";

const PROBE_CERT = "JJ-SENTINEL-PROBE";
const MAX_AGE_S = 90;
const HIST_FILE = "data/history.json";
const STATE_FILE = "data/state.json";
const SITE_DIR = "site";
const HIST_CAP = 2400; // ~1 month at 20-minute cadence

const SG_BASE = "https://www.jiaozi.io";
const CN_BASE = "http://101.37.147.167:3100"; // trial stack; moves to https://www.jiaozi.tech after ICP

// ---------- helpers ----------

function canonicalJson(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  const keys = Object.keys(value).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`;
}

function verifySignature(publicKeyMultibase, message, signatureBase64Url) {
  try {
    const raw = Buffer.from(publicKeyMultibase.replace(/^z/, ""), "base64url");
    const spki = Buffer.concat([Buffer.from("302a300506032b6570032100", "hex"), raw]);
    return edVerify(
      null,
      Buffer.from(message, "utf8"),
      { key: spki, format: "der", type: "spki" },
      Buffer.from(signatureBase64Url, "base64url"),
    );
  } catch {
    return false;
  }
}

async function probe(url, timeoutMs = 12_000) {
  const t0 = Date.now();
  try {
    const res = await fetch(url, { signal: AbortSignal.timeout(timeoutMs), redirect: "follow" });
    const ms = Date.now() - t0;
    let body = null;
    try {
      body = await res.json();
    } catch {
      /* non-JSON is fine for portal checks */
    }
    return { res, body, ms, err: null };
  } catch (err) {
    return { res: null, body: null, ms: Date.now() - t0, err: err?.message ?? String(err) };
  }
}

function loadJson(file, fallback) {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return fallback;
  }
}

// ---------- monitors ----------
// level: "up" (green) | "warn" (yellow) | "down" (red)

const state = loadJson(STATE_FILE, {});
const results = [];

async function checkSgPortal() {
  const { res, ms, err } = await probe(`${SG_BASE}/`);
  if (!res) return { level: "down", detail: `unreachable: ${err}`, ms };
  if (res.status >= 200 && res.status < 400) return { level: "up", detail: `http ${res.status}`, ms };
  return { level: "down", detail: `http ${res.status}`, ms };
}

async function checkSgStatusKey() {
  const { res, body, ms, err } = await probe(`${SG_BASE}/api/status-key`);
  if (!res) return { level: "down", detail: `unreachable: ${err}`, ms };
  if (res.status !== 200 || !body?.publicKeyMultibase) {
    return { level: "down", detail: `http ${res.status}`, ms };
  }
  if (body.ephemeral === true) {
    return { level: "warn", detail: "EPHEMERAL signing key in use", ms };
  }
  return { level: "up", detail: `key ${body.publicKeyMultibase.slice(0, 12)}…`, ms };
}

async function checkSgStatusCredential() {
  const { res, body, ms, err } = await probe(`${SG_BASE}/api/status/${PROBE_CERT}`);
  if (!res) return { level: "down", detail: `unreachable: ${err}`, ms };
  if (res.status !== 200 && res.status !== 404) {
    return { level: "down", detail: `http ${res.status}`, ms };
  }
  const p = body?.payload;
  if (!p || typeof body.signature !== "string" || typeof body.publicKeyMultibase !== "string") {
    return { level: "down", detail: "malformed credential", ms };
  }
  if (!verifySignature(body.publicKeyMultibase, canonicalJson(p), body.signature)) {
    return { level: "down", detail: "BAD SIGNATURE", ms };
  }
  const now = Date.now();
  if (new Date(p.expiresAt).getTime() < now) {
    return { level: "down", detail: `credential expired at ${p.expiresAt}`, ms };
  }
  const ageS = Math.max(0, (now - new Date(p.signedAt).getTime()) / 1000);
  if (ageS > MAX_AGE_S) {
    return { level: "down", detail: `STALE: signed ${ageS.toFixed(0)}s ago`, ms };
  }
  const last = Number(state[`serial:${PROBE_CERT}`] ?? 0);
  if (typeof p.serial === "number" && p.serial < last) {
    return { level: "down", detail: `SERIAL REGRESSION ${p.serial} < ${last}`, ms };
  }
  if (typeof p.serial === "number") state[`serial:${PROBE_CERT}`] = p.serial;
  return { level: "up", detail: `signed, fresh (${ageS.toFixed(1)}s old)`, ms };
}

async function checkCnHealth() {
  const { res, body, ms, err } = await probe(`${CN_BASE}/health`);
  if (!res) return { level: "down", detail: `unreachable: ${err}`, ms };
  if (res.status === 200 && body?.ok === true) return { level: "up", detail: "http 200", ms };
  return { level: "down", detail: `http ${res.status}`, ms };
}

async function checkCnStatusPassthrough() {
  const { res, body, ms, err } = await probe(`${CN_BASE}/api/status/${PROBE_CERT}`);
  if (!res) return { level: "down", detail: `unreachable: ${err}`, ms };
  if (res.status !== 200 && res.status !== 404) {
    return { level: "down", detail: `http ${res.status}`, ms };
  }
  if (body?.degraded === true) {
    return { level: "warn", detail: "DEGRADED: CN serving unsigned replica (SG link down?)", ms };
  }
  if (body?.payload && typeof body.signature === "string") {
    return { level: "up", detail: "signed credential passed through", ms };
  }
  return { level: "warn", detail: "unexpected body shape", ms };
}

const MONITORS = [
  { id: "sg-portal", name: "International portal (www.jiaozi.io)", fn: checkSgPortal },
  { id: "sg-status-key", name: "SG Core signing key disclosure", fn: checkSgStatusKey },
  { id: "sg-status", name: "SG Core signed status credential", fn: checkSgStatusCredential },
  { id: "cn-health", name: "CN trial front (pre-ICP, by IP)", fn: checkCnHealth },
  { id: "cn-status", name: "CN cross-border status passthrough", fn: checkCnStatusPassthrough },
];

for (const m of MONITORS) {
  const r = await m.fn();
  results.push({ id: m.id, name: m.name, ...r });
  console.log(`[${r.level.toUpperCase()}] ${m.id} ${r.detail} (${r.ms}ms)`);
}

// ---------- persist history/state ----------

mkdirSync("data", { recursive: true });
mkdirSync(SITE_DIR, { recursive: true });

const history = loadJson(HIST_FILE, []);
const nowIso = new Date().toISOString();
history.push({
  t: nowIso,
  r: results.map((x) => ({ id: x.id, l: x.level, ms: x.ms })),
});
while (history.length > HIST_CAP) history.shift();
writeFileSync(HIST_FILE, JSON.stringify(history));
writeFileSync(STATE_FILE, JSON.stringify(state, null, 2));

// ---------- render site ----------

function uptime(id, sinceMs) {
  const cutoff = Date.now() - sinceMs;
  const samples = history.filter((h) => new Date(h.t).getTime() >= cutoff);
  if (samples.length === 0) return null;
  const ok = samples.filter((h) => h.r.find((x) => x.id === id)?.l === "up").length;
  return (ok / samples.length) * 100;
}

function fmtUptime(v) {
  return v === null ? "—" : `${v.toFixed(v >= 99.95 ? 2 : 1)}%`;
}

const DAY = 24 * 3600 * 1000;
const levelRank = { up: 0, warn: 1, down: 2 };
const worst = results.reduce((a, b) => (levelRank[b.level] > levelRank[a.level] ? b : a));
const overall =
  worst.level === "up"
    ? { text: "All systems operational", cls: "up" }
    : worst.level === "warn"
      ? { text: "Degraded performance", cls: "warn" }
      : { text: "Service disruption", cls: "down" };

const recentIncidents = [];
for (let i = history.length - 1; i >= 0 && recentIncidents.length < 12; i--) {
  const bad = history[i].r.filter((x) => x.l !== "up");
  if (bad.length > 0) {
    recentIncidents.push({ t: history[i].t, items: bad.map((x) => `${x.id}: ${x.l}`) });
  }
}

const dot = (l) => `<span class="dot ${l}"></span>`;
const rows = results
  .map(
    (r) => `<tr>
      <td>${dot(r.level)} ${r.name}</td>
      <td class="detail">${r.detail}</td>
      <td class="num">${r.ms}ms</td>
      <td class="num">${fmtUptime(uptime(r.id, DAY))}</td>
      <td class="num">${fmtUptime(uptime(r.id, 7 * DAY))}</td>
    </tr>`,
  )
  .join("\n");

const incidentHtml =
  recentIncidents.length === 0
    ? `<p class="quiet">No incidents recorded in the retained window.</p>`
    : `<ul>${recentIncidents
        .map((i) => `<li><code>${i.t}</code> — ${i.items.join(", ")}</li>`)
        .join("")}</ul>`;

const html = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="300">
<title>JIAOZI Status</title>
<style>
  :root { --up:#22c55e; --warn:#eab308; --down:#ef4444; --fg:#111827; --muted:#6b7280; --bg:#f9fafb; --card:#ffffff; }
  body { margin:0; font:16px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif; color:var(--fg); background:var(--bg); }
  .wrap { max-width:860px; margin:0 auto; padding:40px 20px 60px; }
  h1 { font-size:22px; margin:0 0 4px; } .sub { color:var(--muted); font-size:14px; margin-bottom:28px; }
  .banner { border-radius:10px; padding:16px 20px; font-weight:600; color:#fff; margin-bottom:28px; }
  .banner.up { background:var(--up);} .banner.warn { background:var(--warn);} .banner.down { background:var(--down);}
  table { width:100%; border-collapse:collapse; background:var(--card); border-radius:10px; overflow:hidden; box-shadow:0 1px 3px rgba(0,0,0,.08); }
  th,td { text-align:left; padding:12px 14px; border-bottom:1px solid #f1f5f9; font-size:14px; }
  th { background:#f8fafc; color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  tr:last-child td { border-bottom:none; }
  .num { text-align:right; white-space:nowrap; } .detail { color:var(--muted); }
  .dot { display:inline-block; width:10px; height:10px; border-radius:50%; margin-right:8px; vertical-align:baseline; }
  .dot.up { background:var(--up);} .dot.warn { background:var(--warn);} .dot.down { background:var(--down);}
  h2 { font-size:16px; margin:36px 0 12px; }
  .quiet { color:var(--muted); font-size:14px; }
  code { background:#f1f5f9; padding:1px 5px; border-radius:4px; font-size:13px; }
  ul { padding-left:20px; font-size:14px; } li { margin-bottom:6px; }
  footer { margin-top:40px; color:var(--muted); font-size:13px; border-top:1px solid #e5e7eb; padding-top:16px; }
  a { color:#2563eb; text-decoration:none; }
</style>
</head>
<body>
<div class="wrap">
  <h1>JIAOZI Status</h1>
  <div class="sub">Independent revocation-freshness sentinel · runs on GitHub infrastructure, isolated from JIAOZI production regions</div>
  <div class="banner ${overall.cls}">${overall.text}</div>
  <table>
    <thead><tr><th>Monitor</th><th>Last result</th><th>Latency</th><th>24h</th><th>7d</th></tr></thead>
    <tbody>
${rows}
    </tbody>
  </table>
  <h2>Recent incidents</h2>
  ${incidentHtml}
  <footer>
    Last check: <code>${nowIso}</code> (UTC) · every 20 minutes ·
    machine-readable: <a href="status.json">status.json</a> ·
    verifying <code>jiaozi.status.v1</code> Ed25519 signatures against
    <a href="${SG_BASE}/api/status-key">the disclosed signing key</a> ·
    <a href="https://www.jiaozi.io">jiaozi.io</a>
  </footer>
</div>
</body>
</html>
`;

writeFileSync(`${SITE_DIR}/index.html`, html);
writeFileSync(
  `${SITE_DIR}/status.json`,
  JSON.stringify(
    {
      generatedAt: nowIso,
      overall: overall.cls,
      monitors: results.map((r) => ({
        id: r.id,
        name: r.name,
        level: r.level,
        detail: r.detail,
        latencyMs: r.ms,
        uptime24h: uptime(r.id, DAY),
        uptime7d: uptime(r.id, 7 * DAY),
      })),
    },
    null,
    2,
  ),
);

const downCount = results.filter((r) => r.level === "down").length;
if (process.env.GITHUB_OUTPUT) {
  appendFileSync(process.env.GITHUB_OUTPUT, `alerts=${downCount}\n`);
}
console.log(`rendered site/ — overall=${overall.cls}, down=${downCount}`);
