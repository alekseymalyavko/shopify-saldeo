import nodemailer from "nodemailer";
import dotenv from "dotenv";

dotenv.config({ path: ".env.local" });

function cleanEnv(val) {
  return (val || "").replace(/^"|"$/g, "").replace(/\\r|\\n/g, "").trim();
}

const smtpUser = cleanEnv(process.env.SMTP_USER);
const smtpPass = cleanEnv(process.env.SMTP_PASS);
const smtpHost = cleanEnv(process.env.SMTP_HOST) || "smtp.gmail.com";
const smtpPort = Number.parseInt(cleanEnv(process.env.SMTP_PORT), 10) || 587;

const transporter = nodemailer.createTransport({
  host: smtpHost,
  port: smtpPort,
  secure: false,
  auth: {
    user: smtpUser,
    pass: smtpPass,
  },
});

console.log("Testing SMTP with:", {
  host: smtpHost,
  port: smtpPort,
  user: smtpUser,
  passLength: smtpPass.length,
});

await transporter.verify();

await transporter.sendMail({
  from: `"Test" <${smtpUser}>`,
  to: smtpUser,
  subject: "SMTP test",
  text: "SMTP works",
});

console.log("Sent!");
