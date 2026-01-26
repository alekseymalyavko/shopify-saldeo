import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  host: "smtp.gmail.com",
  port: 587,
  secure: false,
  auth: {
    user: "aleksmalyavko@gmail.com",
    pass: "uacuvmbibqoihhri",
  },
});

await transporter.sendMail({
  from: `"Test" <aleksmalyavko@gmail.com>`,
  to: "aleksmalyavko@gmail.com",
  subject: "SMTP test",
  text: "It works 🚀",
});

console.log("Sent!");
