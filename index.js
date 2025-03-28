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

const VALID_APP_IDS = ["100xschool1", "100xschool2"];

app.post("/razorpay-webhook", async (req, res) => {
  const signature = req.headers["x-razorpay-signature"];
  const expectedSignature = crypto
    .createHmac("sha256", WEBHOOK_SECRET)
    .update(req.rawBody)
    .digest("hex");

  if (signature !== expectedSignature) {
    console.log("Signature mismatch");
    return res.status(400).send("Invalid signature");
  }

  const payment = req.body.payload?.payment?.entity;
  if (!payment) return res.status(200).send("No payment entity");

  const appId = payment.notes?.app_id;

  if (!VALID_APP_IDS.includes(appId)) {
    console.log("Ignored payment (app_id mismatch):", payment.id);
    return res.status(200).send("Ignored");
  }

  try {
    await axios.post(LATENODE_WEBHOOK_URL, req.body);
    console.log("Forwarded payment:", payment.id);
    res.status(200).send("Forwarded to Latenode");
  } catch (err) {
    console.error("Error forwarding:", err.message);
    res.status(500).send("Failed to forward");
  }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => console.log(`Razorpay proxy listening on port ${PORT}`));
