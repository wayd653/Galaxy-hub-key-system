// Galaxy Hub — Admin-only key issuer
// Env vars required: SIGNING_SECRET, ADMIN_TOKEN
// Usage (GET):
//   /api/issue?cid=<clientId>&ttl=24&token=<ADMIN_TOKEN>
//   returns: { key: "GH1.<payload>.<sig>", exp: <unix> }

export default function handler(req, res) {
  // CORS
  const allow = process.env.ALLOW_ORIGIN || "*";
  res.setHeader("Access-Control-Allow-Origin", allow === "*" ? "*" : allow);
  res.setHeader("Access-Control-Allow-Methods", "GET,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  if (req.method === "OPTIONS") return res.status(200).end();

  try {
    const secret = process.env.SIGNING_SECRET;
    const admin = process.env.ADMIN_TOKEN;
    if (!secret || !admin) {
      return res.status(500).json({ error: "Server not configured" });
    }

    const { cid = "", ttl = "24", token = "" } = req.query;
    if (token !== admin) return res.status(401).json({ error: "Unauthorized" });

    const ttlHours = Math.max(1, Math.min(24 * 14, parseInt(String(ttl), 10) || 24)); // 1h .. 14d
    const now = Math.floor(Date.now() / 1000);
    const exp = now + ttlHours * 3600;

    // payload can include cid (optional bind)
    const payload = { exp };
    if (cid) payload.cid = String(cid);

    const payloadB64 = base64url(Buffer.from(JSON.stringify(payload), "utf8"));
    const sig = signHS256(`GH1.${payloadB64}`, secret);
    const key = `GH1.${payloadB64}.${sig}`;

    return res.status(200).json({ key, exp });
  } catch {
    return res.status(500).json({ error: "Issue error" });
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
