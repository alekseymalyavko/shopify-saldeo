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
  const match = xml.match(
    new RegExp(String.raw`<${tagName}>([^<]*)</${tagName}>`),
  );
  return match ? match[1] : null;
}

function parseSaldeoError(xml) {
  const status = extractTagValue(xml, "STATUS");
  if (status !== "ERROR") return null;

  const code = extractTagValue(xml, "ERROR_CODE") || "UNKNOWN";
  const message =
    extractTagValue(xml, "ERROR_MESSAGE") || "Unknown Saldeo error";

  if (code === "6001") {
    console.error(
      `[Saldeo 6001] Permission denied: "${message}". Enable this permission in Saldeo user settings.`,
    );
  } else if (code === "4000") {
    console.error(
      `[Saldeo 4000] XSD validation error: "${message}". Check the XML structure.`,
    );
  } else if (code === "5000") {
    console.warn(
      `[Saldeo 5000] Temporary server error: "${message}". Retrying...`,
    );
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
async function pollForPdf(
  pdfUrl,
  initialDelayMs = 5000,
  retryDelayMs = 5000,
  maxAttempts = 6,
) {
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
      const retriable =
        !status || status === 404 || status === 429 || status >= 500;

      if (!retriable || attempt === maxAttempts) {
        throw new Error(
          `PDF unavailable after ${attempt} attempts: ${err?.message}`,
        );
      }

      console.warn(
        `PDF poll ${attempt}/${maxAttempts}: HTTP ${status ?? "network error"}. Waiting ${retryDelayMs}ms...`,
      );
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
      invoiceXml,
    );

    console.log(
      `Saldeo invoice/add response (attempt ${attempt}/${retries}):`,
      createRes,
    );

    const invoiceAddError = parseSaldeoError(createRes);
    if (!invoiceAddError) return createRes;

    lastError = new Error(
      `Saldeo invoice/add failed [${invoiceAddError.code}] ${invoiceAddError.message}. ` +
        `username=${cleanEnv(process.env.SALDEO_USERNAME)}, company_program_id=${cleanEnv(process.env.SALDEO_COMPANY_PROGRAM_ID)}`,
    );

    const retriable = invoiceAddError.code === "5000";
    if (!retriable || attempt === retries) break;

    console.warn(
      `invoice/add temporary server error (attempt ${attempt}/${retries}). Retrying in ${delayMs}ms...`,
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
  const totalGross = parseFloat(order.total_price).toFixed(2);

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
    ${cleanEnv(process.env.SALDEO_CARD_PAYMENT_METHOD_ID)
      ? `<PAYMENT_METHOD_ID>${escapeXml(cleanEnv(process.env.SALDEO_CARD_PAYMENT_METHOD_ID))}</PAYMENT_METHOD_ID>`
      : `<PAYMENT_TYPE>CARD</PAYMENT_TYPE>`}
    <INVOICE_ITEMS>
      ${itemsXml}
    </INVOICE_ITEMS>
    <INVOICE_PAYMENTS>
      <PAYMENT_AMOUNT>${totalGross}</PAYMENT_AMOUNT>
      <PAYMENT_DATE>${escapeXml(issueDate)}</PAYMENT_DATE>
    </INVOICE_PAYMENTS>
  </INVOICE>
</ROOT>`;
}

function buildInvoiceNumber(order) {
  return `NOWAMUZYKA-${order.order_number}`;
}

// =======================
// Saldeo API request
// =======================
function cleanEnv(val) {
  return (val || "")
    .replace(/^"|"$/g, "")
    .replace(/\\r|\\n/g, "")
    .trim();
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
        extraParams[pair.slice(0, eqIdx)] = decodeURIComponent(
          pair.slice(eqIdx + 1),
        );
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
  ]
    .filter(Boolean)
    .join("&");

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
        "Dziękujemy za zakup!",
        `Numer faktury: ${invoiceNumber}`,
        "Faktura w formacie PDF znajduje się w załączniku.",
      ].join("\n")
    : [
        "Dziękujemy za zakup!",
        `Numer faktury: ${invoiceNumber}`,
        "Faktura została wystawiona. W razie potrzeby uzyskania kopii prosimy o kontakt.",
      ].join("\n");

  const html = pdfBuffer
    ? `<p>Dziękujemy za zakup!</p>
<p>Numer faktury: <strong>${escapeXml(invoiceNumber)}</strong></p>
<p>Faktura w formacie PDF znajduje się w załączniku.</p>`
    : `<p>Dziękujemy za zakup!</p>
<p>Numer faktury: <strong>${escapeXml(invoiceNumber)}</strong></p>
<p>Faktura została wystawiona. W razie potrzeby uzyskania kopii prosimy o kontakt.</p>`;

  const mail = {
    from: `"Nowa Muzyka" <${cleanEnv(process.env.SMTP_USER)}>`  ,
    to,
    subject: `Faktura ${invoiceNumber}`,
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
  console.log("Email sent:", {
    to,
    messageId: info.messageId,
    hasAttachment: Boolean(pdfBuffer),
  });
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

function createRequestId() {
  return `${Date.now()}-${crypto.randomBytes(4).toString("hex")}`;
}

function logEvent(level, context, event, details = {}) {
  const payload = {
    ts: new Date().toISOString(),
    level,
    event,
    requestId: context?.requestId || null,
    orderId: context?.orderId || null,
    orderNumber: context?.orderNumber || null,
    invoiceId: context?.invoiceId || null,
    ...details,
  };

  const line = JSON.stringify(payload);
  if (level === "error") {
    console.error(line);
    return;
  }
  if (level === "warn") {
    console.warn(line);
    return;
  }
  console.log(line);
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).send("Method not allowed");

  const requestId = createRequestId();

  const rawBody = await readRawBody(req);
  const hmac = req.headers["x-shopify-hmac-sha256"];

  if (
    !verifyShopifyWebhook(rawBody, hmac, process.env.SHOPIFY_WEBHOOK_SECRET)
  ) {
    logEvent("warn", { requestId }, "webhook.invalid_signature");
    return res.status(401).send("Invalid webhook");
  }

  let order;
  try {
    order = JSON.parse(rawBody.toString("utf8"));
  } catch {
    logEvent("warn", { requestId }, "webhook.invalid_json");
    return res.status(400).send("Bad request: invalid JSON");
  }

  const orderId = String(order.id);
  const context = {
    requestId,
    orderId,
    orderNumber: order.order_number,
    invoiceId: null,
  };

  logEvent("info", context, "webhook.received", {
    email: order.email || null,
    totalPrice: order.total_price || null,
    currency: order.currency || null,
  });

  // Idempotency: skip if this function instance already handled this order
  // (guards against rapid Shopify retries before a cold start resets state)
  if (processedOrders.has(orderId)) {
    const existingInvoiceId = processedOrders.get(orderId);
    context.invoiceId = existingInvoiceId;
    logEvent("info", context, "webhook.duplicate", {
      duplicate: true,
    });
    return res
      .status(200)
      .json({ ok: true, duplicate: true, invoiceId: existingInvoiceId });
  }

  try {
    logEvent("info", context, "saldeo.context", {
      username: cleanEnv(process.env.SALDEO_USERNAME),
      company_program_id: cleanEnv(process.env.SALDEO_COMPANY_PROGRAM_ID),
    });

    // 1️⃣ contractor/merge (idempotent by design — safe to retry)
    const contractorXml = buildContractorMergeXML(order);
    const contractorRes = await saldeoRequest(
      `/api/xml/1.0/contractor/merge?company_program_id=${cleanEnv(process.env.SALDEO_COMPANY_PROGRAM_ID)}`,
      contractorXml,
    );

    const contractorStatus = extractStatuses(contractorRes).find((s) =>
      ["CREATED", "MERGED", "CONFLICT", "RECREATED", "NOT_VALID"].includes(s),
    );
    if (contractorStatus === "CONFLICT" || contractorStatus === "NOT_VALID") {
      throw new Error(
        `contractor/merge failed: ${contractorStatus}. Response: ${contractorRes}`,
      );
    }

    const contractorIdMatch = contractorRes.match(
      /<CONTRACTOR_ID>([^<]+)<\/CONTRACTOR_ID>/,
    );
    if (!contractorIdMatch)
      throw new Error("No CONTRACTOR_ID in Saldeo response: " + contractorRes);
    const contractorId = contractorIdMatch[1];
    logEvent("info", context, "contractor.merge.success", {
      contractorStatus,
      contractorId,
    });

    // 2️⃣ invoice/add
    const invoiceXml = buildInvoiceXML(order, contractorId);
    logEvent("info", context, "invoice.add.start", {
      invoiceNumber: buildInvoiceNumber(order),
    });
    const createRes = await createInvoiceWithRetry(invoiceXml);

    const invoiceIdMatch = createRes.match(/<INVOICE_ID>([^<]+)<\/INVOICE_ID>/);
    if (!invoiceIdMatch)
      throw new Error("No INVOICE_ID in Saldeo response: " + createRes);
    const invoiceId = invoiceIdMatch[1];
    context.invoiceId = invoiceId;
    logEvent("info", context, "invoice.add.success", {
      invoiceId,
    });

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
        listXml,
      );
      const listError = parseSaldeoError(listRes);
      if (listError) {
        logEvent("warn", context, "invoice.listbyid.error", {
          errorCode: listError.code,
          errorMessage: listError.message,
        });
      } else {
        const pdfUrlMatch = listRes.match(/<SOURCE>(.*?)<\/SOURCE>/);
        pdfUrl = pdfUrlMatch ? decodeXmlEntities(pdfUrlMatch[1]) : null;
        logEvent("info", context, "invoice.listbyid.success", {
          hasSource: Boolean(pdfUrl),
        });
      }
    } catch (listErr) {
      logEvent("warn", context, "invoice.listbyid.exception", {
        message: listErr?.message || String(listErr),
      });
    }

    // 4️⃣ Poll for PDF — waits until Saldeo generates the file
    let pdfBuffer = null;
    if (pdfUrl) {
      try {
        logEvent("info", context, "pdf.poll.start");
        pdfBuffer = await pollForPdf(pdfUrl);
        logEvent("info", context, "pdf.poll.success", {
          bytes: pdfBuffer?.length || 0,
        });
      } catch (pollErr) {
        logEvent("warn", context, "pdf.poll.failed", {
          message: pollErr?.message || String(pollErr),
        });
      }
    } else {
      logEvent("warn", context, "pdf.source.missing");
    }

    // 5️⃣ Send email (with PDF attachment if available, plain text if not)
    let emailSent = false;
    let emailError = null;
    try {
      await sendInvoiceEmail(order.email, pdfBuffer, buildInvoiceNumber(order));
      emailSent = true;
      logEvent("info", context, "email.send.success", {
        to: order.email || null,
        hasAttachment: Boolean(pdfBuffer),
      });
    } catch (mailErr) {
      emailError = mailErr?.message || String(mailErr);
      logEvent("error", context, "email.send.failed", {
        message: emailError,
      });
    }

    // ✅ Respond to Shopify only after everything is done
    logEvent("info", context, "webhook.completed", {
      pdfDownloaded: Boolean(pdfBuffer),
      emailSent,
      emailError,
    });
    return res.status(200).json({
      ok: true,
      invoiceId,
      invoiceNumber: buildInvoiceNumber(order),
      pdfDownloaded: Boolean(pdfBuffer),
      emailSent,
      emailError,
    });
  } catch (err) {
    logEvent("error", context, "webhook.failed", {
      message: err?.message || String(err),
    });
    if (!res.headersSent) {
      res.status(500).send("Internal error");
    }
  }
}
