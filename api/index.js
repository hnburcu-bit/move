const crypto = require("crypto");
const RURL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const RTOK = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const SECRET = process.env.AUTH_SECRET;
const AE = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();
const AP = (process.env.ADMIN_PASSWORD || "").trim();

async function redis(cmd) {
  const r = await fetch(RURL, { method: "POST", headers: { Authorization: "Bearer " + RTOK }, body: JSON.stringify(cmd) });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}
const b64 = s => Buffer.from(s).toString("base64url");
const sign = p => crypto.createHmac("sha256", SECRET).update(p).digest("base64url");
const mkToken = o => { const p = b64(JSON.stringify({ ...o, exp: Date.now() + 90 * 864e5 })); return p + "." + sign(p); };
function readToken(h) {
  const t = (h || "").replace("Bearer ", ""), [p, s] = t.split(".");
  if (!p || !s || !same(sign(p), s)) return null;
  const o = JSON.parse(Buffer.from(p, "base64url").toString());
  return o.exp > Date.now() ? o : null;
}
function same(a, b) {
  const x = Buffer.from(String(a)), y = Buffer.from(String(b));
  return x.length === y.length && crypto.timingSafeEqual(x, y);
}
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString("hex");

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  if (req.method !== "POST") return res.status(405).json({ error: "Geçersiz istek" });
  if (!RURL || !RTOK || !SECRET || !AE || !AP) return res.status(500).json({ error: "Sunucu ayarları eksik" });
  const b = req.body || {};
  try {
    if (b.action === "login") {
      const email = String(b.email || "").trim().toLowerCase(), pw = String(b.password || "").trim();
      if (email === AE && same(pw, AP)) return res.json({ token: mkToken({ e: email, a: 1 }), email, admin: true });
      const rec = await redis(["HGET", "users", email]);
      if (rec) {
        const u = JSON.parse(rec);
        if (same(hashPw(pw, u.salt), u.hash)) return res.json({ token: mkToken({ e: email, a: 0 }), email, admin: false });
      }
      return res.status(401).json({ error: "E-posta veya şifre hatalı" });
    }
    const u = readToken(req.headers.authorization);
    if (!u) return res.status(401).json({ error: "Oturum bitti, tekrar giriş yap" });
    const key = "data:" + u.e;
    if (b.action === "load") {
      const d = await redis(["GET", key]);
      return res.json({ data: d ? JSON.parse(d) : null });
    }
    if (b.action === "save") {
      const s = JSON.stringify(b.data || {});
      if (s.length > 900000) return res.status(413).json({ error: "Veri çok büyük" });
      await redis(["SET", key, s]);
      return res.json({ ok: true });
    }
    if (u.a) {
      if (b.action === "users") return res.json({ users: await redis(["HKEYS", "users"]) });
      if (b.action === "adduser") {
        const email = String(b.email || "").trim().toLowerCase(), pw = String(b.password || "");
        if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Geçerli bir e-posta yaz" });
        if (pw.length < 6) return res.status(400).json({ error: "Şifre en az 6 karakter olmalı" });
        if (email === AE) return res.status(400).json({ error: "Bu e-posta yönetici hesabı" });
        const salt = crypto.randomBytes(16).toString("hex");
        await redis(["HSET", "users", email, JSON.stringify({ salt, hash: hashPw(pw, salt) })]);
        return res.json({ ok: true });
      }
    }
    return res.status(400).json({ error: "Bilinmeyen işlem" });
  } catch (e) {
    return res.status(500).json({ error: "Sunucu hatası" });
  }
};

