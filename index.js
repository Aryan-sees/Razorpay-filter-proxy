// Express-based Razorpay Webhook Filter Proxy

const express = require("express");
const crypto = require("crypto");
const axios = require("axios");
const app = express();

// Raw body middleware for signature verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

const WEBHOOK_SECRET = process.env.WEBHOOK_SECRET;
const LATENODE_WEBHOOK_URL = process.env.LATENODE_WEBHOOK_URL;

// Define valid amounts in paise (₹2K and ₹48K)
const VALID_AMOUNTS = [200000, 4800000];

app.post("/razorpay-webhook", async (req, res) => {
  console.log("🔔 Received webhook");
  console.log("Headers:", req.headers);
  console.log("Raw Body:", req.rawBody?.toString());

  const signature = req.headers["x-razorpay-signature"];
  const expectedSignature = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest("hex");

  if (signature !== expectedSignature) {
    console.log("❌ Signature mismatch");
    return res.status(400).send("Invalid signature");
  }

  console.log("✅ Signature verified");
  console.log("Parsed Body:", JSON.stringify(req.body, null, 2));

  const payment = req.body.payload?.payment?.entity;
  if (!payment) {
    console.log("❌ No payment entity in payload");
    return res.status(200).send("No payment entity");
  }

  const amount = payment.amount;
  const appId = payment.notes?.app_id;
  console.log("👀 Detected app_id:", appId || "none");

  if (!VALID_AMOUNTS.includes(amount)) {
    console.log("⚠️ Ignored payment (amount mismatch):", payment.id, "| amount:", amount);
    return res.status(200).send("Ignored");
  }

  try {
    await axios.post(LATENODE_WEBHOOK_URL, req.body);
    console.log("✅ Forwarded payment:", payment.id);
    res.status(200).send("Forwarded to Latenode");
  } catch (err) {
    console.error("❌ Error forwarding:", err.message);
    res.status(500).send("Failed to forward");
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`🚀 Razorpay proxy listening on port ${PORT}`));
