import crypto from "crypto";
import axios from "axios";
import zlib from "zlib";
import nodemailer from "nodemailer";

// Tell Vercel NOT to parse the body — we need the raw bytes to verify Shopify's HMAC signature
export const config = {
  api: {
    bodyParser: false,
  },
};

// In-memory idempotency guard – protects against rapid duplicate webhooks within
// the same function instance (e.g. Shopify retries within seconds).
// For persistent deduplication across cold starts, configure Vercel KV.
const processedOrders = new Map();

// =======================
// Utils — Shopify verify
// =======================
function verifyShopifyWebhook(rawBody, hmacHeader, secret) {
  const digest = crypto
    .createHmac("sha256", secret.trim())
    .update(rawBody)
    .digest("base64");

  return digest === hmacHeader;
}

// =======================
// Utils — Saldeo signing
// =======================
function buildReqSig(params, apiToken) {
  const sorted = Object.keys(params)
    .sort()
    .map((k) => `${k}=${params[k]}`)
    .join("");

  const urlEncoded = encodeURIComponent(sorted);
  return crypto
    .createHash("md5")
    .update(urlEncoded + apiToken)
    .digest("hex");
}

function encodeCommand(xml) {
  const gzipped = zlib.gzipSync(Buffer.from(xml, "utf8"));
  return gzipped.toString("base64");
}

function escapeXml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&apos;");
}

function buildContractorProgramId(order) {
  const customerId = order?.customer?.id;
  if (customerId) return `shopify-customer-${customerId}`;

  const email = (order?.email || "").trim().toLowerCase();
  if (email) return `shopify-email-${email}`;

  if (order?.id) return `shopify-order-${order.id}`;
  if (order?.order_number) return `shopify-order-${order.order_number}`;
  return "shopify-unknown";
}

function buildShortName(name, contractorProgramId) {
  const base = (name || "")
    .normalize("NFD")
    .replaceAll(/[\u0300-\u036f]/g, "")
    .replaceAll(/[^A-Za-z0-9]/g, "")
    .toUpperCase();

  const prefix = (base || "CUST").slice(0, 4);
  const suffix = crypto
    .createHash("md5")
    .update(contractorProgramId)
    .digest("hex")
    .slice(0, 4)
    .toUpperCase();

  return `${prefix}${suffix}`;
}

function extractStatuses(xml) {
  return [...xml.matchAll(/<STATUS>([^<]+)<\/STATUS>/g)].map((m) => m[1]);
}

function extractTagValue(xml, tagName) {
  const match = xml.match(new RegExp(String.raw`<${tagName}>([^<]*)</${tagName}>`));
  return match ? match[1] : null;
}

function parseSaldeoError(xml) {
  const status = extractTagValue(xml, "STATUS");
  if (status !== "ERROR") return null;

  const code = extractTagValue(xml, "ERROR_CODE") || "UNKNOWN";
  const message = extractTagValue(xml, "ERROR_MESSAGE") || "Unknown Saldeo error";

  if (code === "6001") {
    console.error(`[Saldeo 6001] Permission denied: "${message}". Enable this permission in Saldeo user settings.`);
  } else if (code === "4000") {
    console.error(`[Saldeo 4000] XSD validation error: "${message}". Check the XML structure.`);
  } else if (code === "5000") {
    console.warn(`[Saldeo 5000] Temporary server error: "${message}". Retrying...`);
  } else {
    console.error(`[Saldeo ${code}] ${message}`);
  }

  return { code, message };
}

function decodeXmlEntities(value) {
  return (value || "")
    .replaceAll("&amp;", "&")
    .replaceAll("&lt;", "<")
    .replaceAll("&gt;", ">")
    .replaceAll("&quot;", '"')
    .replaceAll("&apos;", "'");
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// Polls the Saldeo SOURCE URL until the PDF file becomes available.
// Saldeo generates PDFs asynchronously after invoice creation (typically ~15–30 seconds).
async function pollForPdf(pdfUrl, initialDelayMs = 5000, retryDelayMs = 5000, maxAttempts = 6) {
  await wait(initialDelayMs);

  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const pdfRes = await axios.get(pdfUrl, {
        responseType: "arraybuffer",
        timeout: 10000,
      });

      if (pdfRes.status === 200 && pdfRes.data?.byteLength > 100) {
        console.log(`PDF ready on poll attempt ${attempt}/${maxAttempts}`);
        return Buffer.from(pdfRes.data);
      }

      throw new Error(`Unexpected status ${pdfRes.status}`);
    } catch (err) {
      const status = err?.response?.status;
      const retriable = !status || status === 404 || status === 429 || status >= 500;

      if (!retriable || attempt === maxAttempts) {
        throw new Error(`PDF unavailable after ${attempt} attempts: ${err?.message}`);
      }

      console.warn(`PDF poll ${attempt}/${maxAttempts}: HTTP ${status ?? "network error"}. Waiting ${retryDelayMs}ms...`);
      await wait(retryDelayMs);
    }
  }

  throw new Error("PDF not available after polling");
}

async function createInvoiceWithRetry(invoiceXml, retries = 3, delayMs = 1500) {
  let lastError;

  for (let attempt = 1; attempt <= retries; attempt += 1) {
    const createRes = await saldeoRequest(
      `/api/xml/3.0/invoice/add?company_program_id=${cleanEnv(process.env.SALDEO_COMPANY_PROGRAM_ID)}`,
      invoiceXml
    );

    console.log(`Saldeo invoice/add response (attempt ${attempt}/${retries}):`, createRes);

    const invoiceAddError = parseSaldeoError(createRes);
    if (!invoiceAddError) return createRes;

    lastError = new Error(
      `Saldeo invoice/add failed [${invoiceAddError.code}] ${invoiceAddError.message}. ` +
      `username=${cleanEnv(process.env.SALDEO_USERNAME)}, company_program_id=${cleanEnv(process.env.SALDEO_COMPANY_PROGRAM_ID)}`
    );

    const retriable = invoiceAddError.code === "5000";
    if (!retriable || attempt === retries) break;

    console.warn(
      `invoice/add temporary server error (attempt ${attempt}/${retries}). Retrying in ${delayMs}ms...`
    );
    await wait(delayMs);
  }

  throw lastError || new Error("Saldeo invoice/add failed");
}

// =======================
// Contractor merge XML builder
// =======================
function buildContractorMergeXML(order) {
  const addr = order.billing_address || {};
  const name = addr.name || order.email;
  const email = (order.email || "").trim().toLowerCase();
  const contractorProgramId = buildContractorProgramId(order);
  // Keep SHORT_NAME compact and highly collision-resistant.
  const shortName = buildShortName(name, contractorProgramId);
  const fullName = addr.company || name || email || "Unknown";

  return `<?xml version="1.0" encoding="UTF-8"?>
<ROOT>
  <CONTRACTORS>
    <CONTRACTOR>
      <CONTRACTOR_PROGRAM_ID>${escapeXml(contractorProgramId)}</CONTRACTOR_PROGRAM_ID>
      <SHORT_NAME>${escapeXml(shortName)}</SHORT_NAME>
      <FULL_NAME>${escapeXml(fullName)}</FULL_NAME>
      <NAME>${escapeXml(name || fullName)}</NAME>
      ${email ? `<EMAIL>${escapeXml(email)}</EMAIL>` : ""}
      <STREET>${escapeXml(addr.address1 || "-")}</STREET>
      <CITY>${escapeXml(addr.city || "-")}</CITY>
      <POSTCODE>${escapeXml(addr.zip || "00-000")}</POSTCODE>
      ${addr.company ? `<COMPANY_NAME>${escapeXml(addr.company)}</COMPANY_NAME>` : ""}
      ${addr.vat_number ? `<NIP>${escapeXml(addr.vat_number)}</NIP>` : ""}
    </CONTRACTOR>
  </CONTRACTORS>
</ROOT>`;
}

// =======================
// Invoice XML builder
// =======================
function buildInvoiceXML(order, contractorId) {
  const issueDate = new Date(order.created_at).toISOString().slice(0, 10);
  const invoiceNumber = buildInvoiceNumber(order);

  const itemsXml = order.line_items
    .map((item) => {
      const vatRate = item.tax_lines?.[0]?.rate
        ? item.tax_lines[0].rate * 100
        : 8;

      const net = Number.parseFloat(item.price) / (1 + vatRate / 100);
      const safeTitle = escapeXml(item.title || "Item");

      return `
        <INVOICE_ITEM>
          <NAME>${safeTitle}</NAME>
          <AMOUNT>${item.quantity}</AMOUNT>
          <UNIT>szt</UNIT>
          <UNIT_VALUE>${net.toFixed(2)}</UNIT_VALUE>
          <RATE>${vatRate}</RATE>
        </INVOICE_ITEM>
      `;
    })
    .join("");

  return `<?xml version="1.0" encoding="UTF-8"?>
<ROOT>
  <INVOICE>
    <NUMBER>${escapeXml(invoiceNumber)}</NUMBER>
    <ISSUE_DATE>${escapeXml(issueDate)}</ISSUE_DATE>
    <SALE_DATE>${escapeXml(issueDate)}</SALE_DATE>
    <DUE_DATE>${escapeXml(issueDate)}</DUE_DATE>
    <PURCHASER_CONTRACTOR_ID>${escapeXml(contractorId)}</PURCHASER_CONTRACTOR_ID>
    <CURRENCY_ISO4217>${escapeXml(order.currency || "PLN")}</CURRENCY_ISO4217>
    <PAYMENT_TYPE>TRANSFER</PAYMENT_TYPE>
    <INVOICE_ITEMS>
      ${itemsXml}
    </INVOICE_ITEMS>
  </INVOICE>
</ROOT>`;
}

function buildInvoiceNumber(order) {
  return `SHOP-${order.order_number}`;
}

// =======================
// Saldeo API request
// =======================
function cleanEnv(val) {
  return (val || "").replace(/^"|"$/g, "").replace(/\\r|\\n/g, "").trim();
}

async function saldeoRequest(path, xml) {
  const req_id = Date.now().toString();
  const username = cleanEnv(process.env.SALDEO_USERNAME);
  const apiToken = cleanEnv(process.env.SALDEO_API_TOKEN);
  const baseUrl = cleanEnv(process.env.SALDEO_BASE_URL);

  const command = encodeCommand(xml);

  // Extract existing query params from path (e.g. company_program_id)
  const qIdx = path.indexOf("?");
  const basePath = qIdx >= 0 ? path.slice(0, qIdx) : path;
  const queryStr = qIdx >= 0 ? path.slice(qIdx + 1) : "";
  const extraParams = {};
  if (queryStr) {
    for (const pair of queryStr.split("&")) {
      const eqIdx = pair.indexOf("=");
      if (eqIdx > 0) {
        extraParams[pair.slice(0, eqIdx)] = decodeURIComponent(pair.slice(eqIdx + 1));
      }
    }
  }

  // Signature MUST include ALL params: command + URL query params + username + req_id
  const sigParams = {
    ...extraParams,
    command,
    req_id,
    username,
  };

  const req_sig = buildReqSig(sigParams, apiToken);

  const urlQuery = [
    queryStr,
    `username=${encodeURIComponent(username)}`,
    `req_id=${req_id}`,
    `req_sig=${req_sig}`,
  ].filter(Boolean).join("&");

  const url = `${baseUrl}${basePath}?${urlQuery}`;

  const res = await axios.post(url, `command=${encodeURIComponent(command)}`, {
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept-Encoding": "gzip, deflate",
    },
  });

  return res.data;
}

// =======================
// Email sender
// =======================
async function sendInvoiceEmail(to, pdfBuffer, invoiceNumber) {
  const transporter = nodemailer.createTransport({
    host: cleanEnv(process.env.SMTP_HOST),
    port: parseInt(cleanEnv(process.env.SMTP_PORT), 10) || 587,
    secure: false,
    auth: {
      user: cleanEnv(process.env.SMTP_USER),
      pass: cleanEnv(process.env.SMTP_PASS),
    },
  });
  const text = pdfBuffer
    ? [
        "Thank you for your purchase!",
        `Invoice number: ${invoiceNumber}`,
        "Your invoice PDF is attached.",
      ].join("\n")
    : [
        "Thank you for your purchase!",
        `Invoice number: ${invoiceNumber}`,
        "Your invoice has been created. Please contact us if you need a copy.",
      ].join("\n");

  const html = pdfBuffer
    ? `<p>Thank you for your purchase!</p>
<p>Invoice number: <strong>${escapeXml(invoiceNumber)}</strong></p>
<p>Your invoice PDF is attached.</p>`
    : `<p>Thank you for your purchase!</p>
<p>Invoice number: <strong>${escapeXml(invoiceNumber)}</strong></p>
<p>Your invoice has been created. Please contact us if you need a copy.</p>`;

  const mail = {
    from: `"Your Company" <${cleanEnv(process.env.SMTP_USER)}>`,
    to,
    subject: `Your invoice ${invoiceNumber}`,
    text,
    html,
  };

  if (pdfBuffer) {
    mail.attachments = [
      {
        filename: `invoice-${invoiceNumber}.pdf`,
        content: pdfBuffer,
      },
    ];
  }

  const info = await transporter.sendMail(mail);
  console.log("Email sent:", { to, messageId: info.messageId, hasAttachment: Boolean(pdfBuffer) });
}

// =======================
// Vercel handler
// =======================
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).send("Method not allowed");

  const rawBody = await readRawBody(req);
  const hmac = req.headers["x-shopify-hmac-sha256"];

  if (!verifyShopifyWebhook(rawBody, hmac, process.env.SHOPIFY_WEBHOOK_SECRET)) {
    console.error("Invalid Shopify webhook signature");
    return res.status(401).send("Invalid webhook");
  }

  let order;
  try {
    order = JSON.parse(rawBody.toString("utf8"));
  } catch {
    return res.status(400).send("Bad request: invalid JSON");
  }

  const orderId = String(order.id);
  console.log("Paid order received:", order.order_number, "| Shopify ID:", orderId);

  // Idempotency: skip if this function instance already handled this order
  // (guards against rapid Shopify retries before a cold start resets state)
  if (processedOrders.has(orderId)) {
    const existingInvoiceId = processedOrders.get(orderId);
    console.log(`Duplicate webhook for order ${order.order_number}. Invoice ID: ${existingInvoiceId}`);
    return res.status(200).json({ ok: true, duplicate: true, invoiceId: existingInvoiceId });
  }

  try {
    console.log("Saldeo context:", {
      username: cleanEnv(process.env.SALDEO_USERNAME),
      company_program_id: cleanEnv(process.env.SALDEO_COMPANY_PROGRAM_ID),
    });

    // 1️⃣ contractor/merge (idempotent by design — safe to retry)
    const contractorXml = buildContractorMergeXML(order);
    const contractorRes = await saldeoRequest(
      `/api/xml/1.0/contractor/merge?company_program_id=${cleanEnv(process.env.SALDEO_COMPANY_PROGRAM_ID)}`,
      contractorXml
    );

    const contractorStatus = extractStatuses(contractorRes).find((s) =>
      ["CREATED", "MERGED", "CONFLICT", "RECREATED", "NOT_VALID"].includes(s)
    );
    if (contractorStatus === "CONFLICT" || contractorStatus === "NOT_VALID") {
      throw new Error(`contractor/merge failed: ${contractorStatus}. Response: ${contractorRes}`);
    }

    const contractorIdMatch = contractorRes.match(/<CONTRACTOR_ID>([^<]+)<\/CONTRACTOR_ID>/);
    if (!contractorIdMatch) throw new Error("No CONTRACTOR_ID in Saldeo response: " + contractorRes);
    const contractorId = contractorIdMatch[1];
    console.log("contractor/merge:", contractorStatus, "| CONTRACTOR_ID:", contractorId);

    // 2️⃣ invoice/add
    const invoiceXml = buildInvoiceXML(order, contractorId);
    console.log("invoice/add number:", buildInvoiceNumber(order));
    const createRes = await createInvoiceWithRetry(invoiceXml);

    const invoiceIdMatch = createRes.match(/<INVOICE_ID>([^<]+)<\/INVOICE_ID>/);
    if (!invoiceIdMatch) throw new Error("No INVOICE_ID in Saldeo response: " + createRes);
    const invoiceId = invoiceIdMatch[1];
    console.log("invoice/add OK | INVOICE_ID:", invoiceId);

    // Mark order as processed to block duplicates on rapid retries
    processedOrders.set(orderId, invoiceId);
    if (processedOrders.size > 500) {
      processedOrders.delete(processedOrders.keys().next().value);
    }

    // 3️⃣ Get SOURCE URL via listbyid (fast — returns URL even before PDF is ready)
    let pdfUrl = null;
    try {
      const listXml = `<?xml version="1.0" encoding="UTF-8"?>
<ROOT>
  <INVOICES>
    <INVOICE_ID>${invoiceId}</INVOICE_ID>
  </INVOICES>
</ROOT>`;
      const listRes = await saldeoRequest(
        `/api/xml/3.0/invoice/listbyid?company_program_id=${cleanEnv(process.env.SALDEO_COMPANY_PROGRAM_ID)}`,
        listXml
      );
      const listError = parseSaldeoError(listRes);
      if (listError) {
        console.warn(`invoice/listbyid error [${listError.code}]: ${listError.message}`);
      } else {
        const pdfUrlMatch = listRes.match(/<SOURCE>(.*?)<\/SOURCE>/);
        pdfUrl = pdfUrlMatch ? decodeXmlEntities(pdfUrlMatch[1]) : null;
        console.log("invoice/listbyid OK | SOURCE:", pdfUrl);
      }
    } catch (listErr) {
      console.warn("invoice/listbyid failed (non-fatal):", listErr?.message);
    }

    // 4️⃣ Poll for PDF — waits until Saldeo generates the file
    let pdfBuffer = null;
    if (pdfUrl) {
      try {
        pdfBuffer = await pollForPdf(pdfUrl);
      } catch (pollErr) {
        console.warn("PDF not ready after polling:", pollErr?.message);
      }
    } else {
      console.warn("No SOURCE URL available — skipping PDF download");
    }

    // 5️⃣ Send email (with PDF attachment if available, plain text if not)
    let emailSent = false;
    let emailError = null;
    try {
      await sendInvoiceEmail(order.email, pdfBuffer, buildInvoiceNumber(order));
      emailSent = true;
    } catch (mailErr) {
      emailError = mailErr?.message || String(mailErr);
      console.error("Email failed (invoice was created):", emailError);
    }

    // ✅ Respond to Shopify only after everything is done
    return res.status(200).json({
      ok: true,
      invoiceId,
      invoiceNumber: buildInvoiceNumber(order),
      pdfDownloaded: Boolean(pdfBuffer),
      emailSent,
      emailError,
    });

  } catch (err) {
    console.error("Webhook processing failed:", err?.message || err);
    if (!res.headersSent) {
      res.status(500).send("Internal error");
    }
  }
}
