/**
 * test-webhook.js
 *
 * Simulates a Shopify "orders/paid" webhook call to your deployed Vercel endpoint.
 * It correctly signs the request with HMAC-SHA256 so the handler accepts it.
 *
 * Usage:
 *   node test-webhook.js [YOUR_VERCEL_URL] [RECIPIENT_EMAIL]
 *
 * Example:
 *   node test-webhook.js https://shopify-saldeo-xyz.vercel.app
 *
 * The SHOPIFY_WEBHOOK_SECRET is read from .env.example automatically.
 */

import crypto from "crypto";
import { readFileSync } from "fs";

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const VERCEL_URL = process.argv[2];
const RECIPIENT_EMAIL = process.argv[3] || "aleksmalyavko@gmail.com";

if (!VERCEL_URL) {
  console.error(
    "Usage: node test-webhook.js <YOUR_VERCEL_URL>\n" +
    "Example: node test-webhook.js https://shopify-saldeo-xyz.vercel.app"
  );
  process.exit(1);
}

const WEBHOOK_ENDPOINT = `${VERCEL_URL.replace(/\/$/, "")}/api/shopify-webhook`;

// Read the secret from .env.example (fill it in there if not already)
const envFile = readFileSync(".env.example", "utf8");
const secretMatch = envFile.match(/SHOPIFY_WEBHOOK_SECRET=(.+)/);
if (!secretMatch) {
  console.error("SHOPIFY_WEBHOOK_SECRET not found in .env.example");
  process.exit(1);
}
const SHOPIFY_WEBHOOK_SECRET = secretMatch[1].trim();

// ---------------------------------------------------------------------------
// Fake order payload (mirrors what Shopify sends for a paid order)
// ---------------------------------------------------------------------------

const testSeed = Date.now();
const testOrderId = Number(`82${String(testSeed).slice(-12)}`);
const testOrderNumber = Number(String(testSeed).slice(-6));

const order = {
  id: testOrderId,
  order_number: testOrderNumber,
  created_at: new Date().toISOString(),
  currency: "PLN",
  total_price: "123.00",
  email: RECIPIENT_EMAIL,
  billing_address: {
    name: "Jan Kowalski",
    company: "",
    address1: "ul. Testowa 1",
    city: "Warszawa",
    zip: "00-001",
    vat_number: "321",
  },
  note_attributes: [
    { name: "NIP", value: "5213992583" },
    // { name: "company_name", value: "Jan Kowalski Test Company" },
  ],
  line_items: [
    {
      id: 122,
      title: "Event Ticket - Test Concert",
      quantity: 1,
      price: "123.00",
      tax_lines: [{ rate: 0.08, price: "8.00" }],
    },
  ],
};

// ---------------------------------------------------------------------------
// Sign the body exactly as Shopify does
// ---------------------------------------------------------------------------

const body = JSON.stringify(order);
const hmac = crypto
  .createHmac("sha256", SHOPIFY_WEBHOOK_SECRET)
  .update(body, "utf8")
  .digest("base64");

// ---------------------------------------------------------------------------
// Send the request
// ---------------------------------------------------------------------------

console.log(`\nSending test webhook to: ${WEBHOOK_ENDPOINT}`);
console.log(`Order #${order.order_number} — ${order.email}\n`);

const response = await fetch(WEBHOOK_ENDPOINT, {
  method: "POST",
  headers: {
    "Content-Type": "application/json",
    "X-Shopify-Hmac-Sha256": hmac,
    "X-Shopify-Topic": "orders/paid",
    "X-Shopify-Shop-Domain": "test.myshopify.com",
  },
  body,
});

const text = await response.text();
console.log(`Response: ${response.status} ${response.statusText}`);
console.log(`Body: ${text}`);

if (response.ok) {
  console.log("\n✅ Webhook accepted! Check your email for the invoice.");
} else if (response.status === 401) {
  console.log("\n❌ Signature rejected — check SHOPIFY_WEBHOOK_SECRET in Vercel env vars.");
} else {
  console.log("\n❌ Error — check Vercel function logs for details.");
  console.log("   npx vercel logs --prod");
}
