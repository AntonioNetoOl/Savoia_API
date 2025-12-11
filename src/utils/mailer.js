// src/utils/mailer.js
const nodemailer = require("nodemailer");

const hasSmtp =
  process.env.SMTP_HOST &&
  process.env.SMTP_PORT &&
  process.env.SMTP_USER &&
  process.env.SMTP_PASS;

let transporter = null;

if (hasSmtp) {
  transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT),
    secure: Number(process.env.SMTP_PORT) === 465,
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS },
  });
}

async function sendMail({ to, subject, html }) {
  if (!hasSmtp) {
    console.log("\n📧 [DEV MAIL] (sem SMTP configurado)");
    console.log("To:", to);
    console.log("Subject:", subject);
    console.log(html, "\n");
    return true;
  }
  await transporter.sendMail({
    from: process.env.SMTP_FROM || `"Savóia" <no-reply@savoia.com.br>`,
    to,
    subject,
    html,
  });
  return true;
}

module.exports = { sendMail };
