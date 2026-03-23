import express from "express";
import bodyParser from "body-parser";
import crypto from "crypto";
import axios from "axios";
import zlib from "zlib";
import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config();
const app = express();

// --- RAW body for Shopify signature verification ---
app.use(
  bodyParser.raw({
    type: "application/json",
  })
);

// ========================
// Shopify webhook verifier
// ========================
function verifyShopifyWebhook(req, res, buf) {
  const hmac = req.get("X-Shopify-Hmac-Sha256");
  const digest = crypto
    .createHmac("sha256", process.env.SHOPIFY_WEBHOOK_SECRET)
    .update(buf)
    .digest("base64");

  if (digest !== hmac) {
    throw new Error("Invalid Shopify webhook signature");
  }
}

// middleware wrapper
app.use((req, res, next) => {
  try {
    verifyShopifyWebhook(req, res, req.body);
    next();
  } catch (err) {
    console.error("Webhook verification failed:", err.message);
    res.status(401).send("Invalid webhook");
  }
});

// ========================
// Utils — Saldeo signing
// ========================
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

// gzip + base64 encoder
function encodeCommand(xml) {
  const gzipped = zlib.gzipSync(Buffer.from(xml, "utf8"));
  return gzipped.toString("base64");
}

// ========================
// Saldeo — invoice.add XML
// ========================
function buildInvoiceXML(order) {
  const issueDate = new Date(order.created_at).toISOString().slice(0, 10);

  const itemsXml = order.line_items
    .map((item) => {
      const vatRate = item.tax_lines?.[0]?.rate
        ? item.tax_lines[0].rate * 100
        : 23;

      const net =
        parseFloat(item.price) /
        (1 + vatRate / 100);

      return `
        <ITEM>
          <NAME>${item.title}</NAME>
          <QUANTITY>${item.quantity}</QUANTITY>
          <NET_PRICE>${net.toFixed(2)}</NET_PRICE>
          <VAT_RATE>${vatRate}</VAT_RATE>
        </ITEM>
      `;
    })
    .join("");

  return `<?xml version="1.0" encoding="UTF-8"?>
<ROOT>
  <INVOICES>
    <INVOICE>
      <NUMBER>NOWAMUZYKA-${order.order_number}</NUMBER>
      <ISSUE_DATE>${issueDate}</ISSUE_DATE>
      <SALE_DATE>${issueDate}</SALE_DATE>
      <PAYMENT_METHOD>Online payment</PAYMENT_METHOD>
      <PAYMENT_DUE_DATE>${issueDate}</PAYMENT_DUE_DATE>
      <CURRENCY>${order.currency}</CURRENCY>

      <CONTRACTOR>
        <NAME>${order.billing_address?.name || order.email}</NAME>
        <EMAIL>${order.email}</EMAIL>
        ${
          order.billing_address?.company
            ? `<COMPANY_NAME>${order.billing_address.company}</COMPANY_NAME>`
            : ""
        }
        ${
          order.billing_address?.vat_number
            ? `<NIP>${order.billing_address.vat_number}</NIP>`
            : ""
        }
      </CONTRACTOR>

      <ITEMS>
        ${itemsXml}
      </ITEMS>
    </INVOICE>
  </INVOICES>
</ROOT>`;
}

// ========================
// Saldeo API calls
// ========================
async function saldeoRequest(path, xml) {
  const req_id = Date.now().toString();
  const username = process.env.SALDEO_USERNAME;
  const apiToken = process.env.SALDEO_API_TOKEN;

  const command = encodeCommand(xml);

  const params = {
    username,
    req_id,
    command,
  };

  const req_sig = buildReqSig(params, apiToken);

  const url = `${process.env.SALDEO_BASE_URL}${path}?username=${username}&req_id=${req_id}&req_sig=${req_sig}`;

  const res = await axios.post(url, `command=${encodeURIComponent(command)}`, {
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      "Accept-Encoding": "gzip, deflate",
    },
  });

  return res.data;
}

// ========================
// Email sender
// ========================
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

async function sendInvoiceEmail(to, pdfBuffer, invoiceNumber) {
  await transporter.sendMail({
    from: `"Your Company" <${process.env.SMTP_USER}>`,
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

// ========================
// Main webhook endpoint
// ========================
app.post("/webhook/shopify/order-paid", async (req, res) => {
  try {
    const order = JSON.parse(req.body.toString());

    console.log("New paid order:", order.id);

    // 1️⃣ Create invoice in Saldeo
    const invoiceXml = buildInvoiceXML(order);
    const createRes = await saldeoRequest(
      `/api/xml/3.0/invoice/add?company_program_id=${process.env.SALDEO_COMPANY_PROGRAM_ID}`,
      invoiceXml
    );

    console.log("Saldeo create invoice response:", createRes);

    const invoiceIdMatch = createRes.match(/<INVOICE_ID>(\d+)<\/INVOICE_ID>/);
    if (!invoiceIdMatch) throw new Error("Invoice ID not returned by Saldeo");
    const invoiceId = invoiceIdMatch[1];

    // 2️⃣ Get invoice PDF
    const listXml = `<?xml version="1.0" encoding="UTF-8"?>
<ROOT>
  <INVOICE_IDS>
    <INVOICE_ID>${invoiceId}</INVOICE_ID>
  </INVOICE_IDS>
</ROOT>`;

    const listRes = await saldeoRequest(
      `/api/xml/3.0/invoice/listbyid?company_program_id=${process.env.SALDEO_COMPANY_PROGRAM_ID}`,
      listXml
    );

    const pdfUrlMatch = listRes.match(/<SOURCE>(.*?)<\/SOURCE>/);
    if (!pdfUrlMatch) throw new Error("PDF URL not found");
    const pdfUrl = pdfUrlMatch[1];

    const pdfRes = await axios.get(pdfUrl, { responseType: "arraybuffer" });
    const pdfBuffer = Buffer.from(pdfRes.data);

    // 3️⃣ Send email
    await sendInvoiceEmail(order.email, pdfBuffer, `NOWAMUZYKA-${order.order_number}`);

    res.status(200).send("OK");
  } catch (err) {
    console.error("Webhook processing failed:", err);
    res.status(500).send("Internal error");
  }
});

// ========================
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
});
