/**
 * diagnose-saldeo.js
 * Lists all companies available in your Saldeo account.
 * Run: node diagnose-saldeo.js
 */
import crypto from "crypto";
import zlib from "zlib";
import axios from "axios";
import { readFileSync } from "fs";

// Read credentials from .env.local
const raw = Object.fromEntries(
  readFileSync(".env.local", "utf8")
    .split(/\r?\n/)
    .filter((l) => l.includes("=") && !l.startsWith("#") && !l.startsWith("//"))
    .map((l) => {
      const idx = l.indexOf("=");
      return [l.slice(0, idx).trim(), l.slice(idx + 1)];
    })
);
// Strip enclosing quotes first, then trim (same as cleanEnv in webhook)
const clean = (v) => (v || "").replace(/^"|"$/g, "").replace(/\\r|\\n/g, "").trim();
const env = Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, clean(v)]));

const BASE_URL = env.SALDEO_BASE_URL;
const USERNAME = env.SALDEO_USERNAME;
const API_TOKEN = env.SALDEO_API_TOKEN;

function buildReqSig(params, apiToken) {
  const sorted = Object.keys(params).sort().map((k) => `${k}=${params[k]}`).join("");
  const urlEncoded = encodeURIComponent(sorted);
  return crypto.createHash("md5").update(urlEncoded + apiToken).digest("hex");
}

function encodeCommand(xml) {
  return zlib.gzipSync(Buffer.from(xml, "utf8")).toString("base64");
}

async function get(path) {
  const req_id = Date.now().toString();
  const params = { req_id, username: USERNAME };
  const req_sig = buildReqSig(params, API_TOKEN);
  const url = `${BASE_URL}${path}?username=${USERNAME}&req_id=${req_id}&req_sig=${req_sig}`;
  const res = await axios.get(url, { headers: { "Accept-Encoding": "gzip, deflate" } });
  return res.data;
}

async function post(path, xml) {
  const req_id = Date.now().toString();
  const command = encodeCommand(xml);
  const params = { command, req_id, username: USERNAME };
  const req_sig = buildReqSig(params, API_TOKEN);
  const url = `${BASE_URL}${path}?username=${USERNAME}&req_id=${req_id}&req_sig=${req_sig}`;
  const res = await axios.post(url, `command=${encodeURIComponent(command)}`, {
    headers: { "Content-Type": "application/x-www-form-urlencoded", "Accept-Encoding": "gzip, deflate" },
  });
  return res.data;
}

console.log("Credentials:");
console.log("  BASE_URL:", BASE_URL);
console.log("  USERNAME:", USERNAME);
console.log("  API_TOKEN:", API_TOKEN ? API_TOKEN.slice(0, 4) + "****" : "MISSING");
console.log("");

console.log("=== POST /api/xml/1.0/company/synchronize ===");
// Links COMPANY_PROGRAM_ID ("1194860") to the internal COMPANY_ID ("1194860")
const syncXml = `<?xml version="1.0" encoding="UTF-8"?>
<ROOT>
  <COMPANIES>
    <COMPANY>
      <COMPANY_ID>1194860</COMPANY_ID>
      <COMPANY_PROGRAM_ID>1194860</COMPANY_PROGRAM_ID>
    </COMPANY>
  </COMPANIES>
</ROOT>`;
try {
  const res = await post("/api/xml/1.0/company/synchronize", syncXml);
  console.log(res);
} catch (e) {
  console.log("ERROR:", e.message);
}

console.log("\n=== GET /api/xml/1.0/company/list ===");
try {
  const res = await get("/api/xml/1.0/company/list");
  console.log(res);
} catch (e) {
  console.log("ERROR:", e.message);
}
