/**
 * test-webhook.js
 *
 * Simulates a Shopify "orders/paid" webhook call to your deployed Vercel endpoint.
 * It correctly signs the request with HMAC-SHA256 so the handler accepts it.
 *
 * Usage:
 *   node test-webhook.js [YOUR_VERCEL_URL]
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

const order = {
  id: 820982911946154500,
  order_number: 1001,
  created_at: new Date().toISOString(),
  currency: "PLN",
  total_price: "123.00",
  email: "aleksmalyavko@gmail.com",
  billing_address: {
    name: "Jan Kowalski",
    company: "",
    address1: "ul. Testowa 1",
    city: "Warszawa",
    zip: "00-001",
    vat_number: "",
  },
  line_items: [
    {
      id: 1,
      title: "Event Ticket — Test Concert",
      quantity: 1,
      price: "123.00",
      tax_lines: [{ rate: 0.23, price: "23.00" }],
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
