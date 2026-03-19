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

  return {
    code: extractTagValue(xml, "ERROR_CODE") || "UNKNOWN",
    message: extractTagValue(xml, "ERROR_MESSAGE") || "Unknown Saldeo error",
  };
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

  const itemsXml = order.line_items
    .map((item) => {
      const vatRate = item.tax_lines?.[0]?.rate
        ? item.tax_lines[0].rate * 100
        : 23;

      const net = parseFloat(item.price) / (1 + vatRate / 100);

      return `
        <INVOICE_ITEM>
          <NAME>${item.title}</NAME>
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
    <NUMBER>SHOP-${order.order_number}</NUMBER>
    <ISSUE_DATE>${issueDate}</ISSUE_DATE>
    <SALE_DATE>${issueDate}</SALE_DATE>
    <DUE_DATE>${issueDate}</DUE_DATE>
    <PURCHASER_CONTRACTOR_ID>${contractorId}</PURCHASER_CONTRACTOR_ID>
    <CURRENCY_ISO4217>${order.currency}</CURRENCY_ISO4217>
    <PAYMENT_TYPE>TRANSFER</PAYMENT_TYPE>
    <INVOICE_ITEMS>
      ${itemsXml}
    </INVOICE_ITEMS>
  </INVOICE>
</ROOT>`;
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
  await transporter.sendMail({
    from: `"Your Company" <${cleanEnv(process.env.SMTP_USER)}>`,
    to,
    subject: `Your invoice ${invoiceNumber}`,
    text: `Thank you for your purchase! Your invoice is attached.`,
    attachments: [
      {
        filename: `invoice-${invoiceNumber}.pdf`,
        content: pdfBuffer,
      },
    ],
  });
}

// =======================
// Vercel handler
// =======================
// Helper to read the full raw body from a Node.js IncomingMessage stream
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

  // Read raw bytes before any JSON parsing so the HMAC check works
  const rawBody = await readRawBody(req);
  const hmac = req.headers["x-shopify-hmac-sha256"];

  if (
    !verifyShopifyWebhook(
      rawBody,
      hmac,
      process.env.SHOPIFY_WEBHOOK_SECRET
    )
  ) {
    console.error("Invalid Shopify webhook signature");
    return res.status(401).send("Invalid webhook");
  }

  try {
    const order = JSON.parse(rawBody.toString("utf8"));
    console.log("New paid order:", order.order_number);

    // 1️⃣ Ensure contractor exists in Saldeo (upsert), get numeric CONTRACTOR_ID
    const contractorXml = buildContractorMergeXML(order);
    const contractorRes = await saldeoRequest(
      `/api/xml/1.0/contractor/merge?company_program_id=${cleanEnv(process.env.SALDEO_COMPANY_PROGRAM_ID)}`,
      contractorXml
    );
    console.log("Saldeo contractor/merge response:", contractorRes);

    const contractorEntityStatus = extractStatuses(contractorRes).find((s) =>
      ["CREATED", "MERGED", "CONFLICT", "RECREATED", "NOT_VALID"].includes(s)
    );
    if (contractorEntityStatus === "CONFLICT" || contractorEntityStatus === "NOT_VALID") {
      throw new Error(`Contractor merge failed with status ${contractorEntityStatus}. Response: ${contractorRes}`);
    }

    const contractorIdMatch = contractorRes.match(/<CONTRACTOR_ID>([^<]+)<\/CONTRACTOR_ID>/);
    if (!contractorIdMatch) throw new Error("Contractor ID not returned by Saldeo. Response: " + contractorRes);
    const contractorId = contractorIdMatch[1];

    // 2️⃣ Create invoice in Saldeo
    const invoiceXml = buildInvoiceXML(order, contractorId);
    const createRes = await saldeoRequest(
      `/api/xml/3.0/invoice/add?company_program_id=${cleanEnv(process.env.SALDEO_COMPANY_PROGRAM_ID)}`,
      invoiceXml
    );

    console.log("Saldeo invoice/add response:", createRes);

    const invoiceAddError = parseSaldeoError(createRes);
    if (invoiceAddError) {
      throw new Error(
        `Saldeo invoice/add failed [${invoiceAddError.code}] ${invoiceAddError.message}. ` +
        `username=${cleanEnv(process.env.SALDEO_USERNAME)}, company_program_id=${cleanEnv(process.env.SALDEO_COMPANY_PROGRAM_ID)}`
      );
    }

    const invoiceIdMatch = createRes.match(/<INVOICE_ID>([^<]+)<\/INVOICE_ID>/);
    if (!invoiceIdMatch) throw new Error("Invoice ID not returned by Saldeo. Response: " + createRes);
    const invoiceId = invoiceIdMatch[1];

    // 3️⃣ Get invoice PDF
    const listXml = `<?xml version="1.0" encoding="UTF-8"?>
<ROOT>
  <INVOICE_IDS>
    <INVOICE_ID>${invoiceId}</INVOICE_ID>
  </INVOICE_IDS>
</ROOT>`;

    const listRes = await saldeoRequest(
      `/api/xml/3.0/invoice/listbyid?company_program_id=${cleanEnv(process.env.SALDEO_COMPANY_PROGRAM_ID)}`,
      listXml
    );

    const listError = parseSaldeoError(listRes);
    if (listError) {
      throw new Error(
        `Saldeo invoice/listbyid failed [${listError.code}] ${listError.message}. ` +
        `invoice_id=${invoiceId}`
      );
    }

    const pdfUrlMatch = listRes.match(/<SOURCE>(.*?)<\/SOURCE>/);
    if (!pdfUrlMatch) throw new Error("PDF URL not found in Saldeo response");
    const pdfUrl = pdfUrlMatch[1];

    const pdfRes = await axios.get(pdfUrl, { responseType: "arraybuffer" });
    const pdfBuffer = Buffer.from(pdfRes.data);

    // 4️⃣ Send email
    await sendInvoiceEmail(order.email, pdfBuffer, `SHOP-${order.order_number}`);

    res.status(200).send("OK");
  } catch (err) {
    console.error("Webhook processing failed:", err);
    res.status(500).send("Internal error");
  }
}
