// Galaxy Hub — Key Validation (stateless, HS256 signed keys)
// Env vars required on Vercel: SIGNING_SECRET, (optional) ALLOW_ORIGIN
// Key format: GH1.<base64url(json payload)>.<base64url(signature)>
// payload example: { cid:"client-id", exp: 1735689600 } // Unix seconds (UTC)

export default function handler(req, res) {
  // --- CORS (allow Roblox exploit environments to call this) ---
  const origin = req.headers.origin || "*";
  const allow = process.env.ALLOW_ORIGIN || "*";
  res.setHeader("Access-Control-Allow-Origin", allow === "*" ? "*" : allow);
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  if (req.method === "OPTIONS") return res.status(200).end();

  try {
    const secret = process.env.SIGNING_SECRET;
    if (!secret) {
      return res.status(500).json({ valid: false, message: "Server not configured" });
    }

    const { key, cid } = req.query;
    if (!key) {
      return res.status(400).json({ valid: false, message: "No key provided" });
    }

    // Expect "GH1.<payload>.<sig>"
    const parts = String(key).split(".");
    if (parts.length !== 3 || parts[0] !== "GH1") {
      return res.status(200).json({ valid: false, message: "Invalid format" });
    }
    const payloadB64 = parts[1];
    const sigB64 = parts[2];

    const payloadJson = b64urlDecode(payloadB64);
    let payload;
    try { payload = JSON.parse(payloadJson); } catch {
      return res.status(200).json({ valid: false, message: "Bad payload" });
    }

    // Verify signature
    const expectedSig = signHS256(`GH1.${payloadB64}`, secret);
    if (sigB64 !== expectedSig) {
      return res.status(200).json({ valid: false, message: "Bad signature" });
    }

    // Check expiration
    const now = Math.floor(Date.now() / 1000);
    if (!payload.exp || now >= payload.exp) {
      return res.status(200).json({ valid: false, message: "Key expired" });
    }

    // Optional bind to client id
    if (payload.cid && cid && payload.cid !== cid) {
      return res.status(200).json({ valid: false, message: "CID mismatch" });
    }

    return res.status(200).json({ valid: true, message: "Access granted!" });
  } catch (e) {
    return res.status(200).json({ valid: false, message: "Validation error" });
  }
}

// ---- helpers ----
function signHS256(data, secret) {
  const crypto = require("crypto");
  const h = crypto.createHmac("sha256", Buffer.from(secret, "utf8"))
                  .update(Buffer.from(data, "utf8"))
                  .digest();
  return base64url(h);
}
function base64url(buf) {
  return Buffer.from(buf).toString("base64")
    .replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}
function b64urlDecode(s) {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  const pad = s.length % 4 ? 4 - (s.length % 4) : 0;
  return Buffer.from(s + "=".repeat(pad), "base64").toString("utf8");
    }
