import "dotenv/config";

import nodemailer from "nodemailer";
import PDFDocument from "pdfkit";

console.log("SMTP_HOST:", process.env.SMTP_HOST);

// =======================
// Dummy PDF generator
// =======================
function generateDummyPDF(order) {
  return new Promise((resolve) => {
    const doc = new PDFDocument();
    const buffers = [];

    doc.on("data", buffers.push.bind(buffers));
    doc.on("end", () => {
      resolve(Buffer.concat(buffers));
    });

    doc.fontSize(20).text("INVOICE (TEST)", { align: "center" });
    doc.moveDown();
    doc.fontSize(12).text(`Order #: ${order.order_number}`);
    doc.text(`Customer: ${order.email}`);
    doc.text(`Date: ${new Date(order.created_at).toLocaleDateString()}`);
    doc.moveDown();

    order.line_items.forEach((item) => {
      doc.text(
        `${item.title} — ${item.quantity} × ${item.price} ${order.currency}`
      );
    });

    doc.moveDown();
    doc.text(`Total: ${order.total_price} ${order.currency}`);

    doc.end();
  });
}

// =======================
// Email sender
// =======================
const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: process.env.SMTP_PORT,
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
});

// =======================
// Vercel handler
// =======================
export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).send("Method not allowed");

  try {
    const order = req.body; // ← ВАЖНО: теперь просто так
    console.log("New paid order:", order.order_number);

    const pdfBuffer = await generateDummyPDF(order);

    await transporter.sendMail({
      from: `"Your Company" <${process.env.SMTP_USER}>`,
      to: order.email,
      subject: `Your invoice ${order.order_number}`,
      text: `Thank you for your purchase! Your invoice is attached.`,
      attachments: [
        {
          filename: `invoice-${order.order_number}.pdf`,
          content: pdfBuffer,
        },
      ],
    });

    res.status(200).send("OK");
  } catch (err) {
    console.error("Webhook failed:", err);
    res.status(500).send("Internal error");
  }
}
