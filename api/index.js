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
const CH = ["work", "meals", "checks", "water", "cf"];
const pj = s => { try { return s ? JSON.parse(s) : null; } catch (e) { return null; } };
async function loadAll(email) {
  const core = pj(await redis(["GET", "data:" + email]));
  const flat = (await redis(["HGETALL", "mon:" + email])) || [], months = {};
  for (let i = 0; i < flat.length; i += 2) { const v = pj(flat[i + 1]); if (v) months[flat[i]] = v; }
  return { core, months };
}
function mergeData(core, months) {
  const D = core ? { ...core } : {};
  CH.forEach(k => { D[k] = { ...(D[k] || {}) }; });
  Object.keys(months).sort().forEach(m => CH.forEach(k => Object.assign(D[k], (months[m] || {})[k] || {})));
  return D;
}
function digest(D, dates7) {
  const W = D.work || {}, C = D.checks || {}, M = D.meals || {}, days = new Set(), act = new Set();
  Object.keys(W).forEach(d => { if ((W[d] || []).length) { days.add(d); act.add(d); } });
  Object.keys(M).forEach(d => { if ((M[d] || []).length) act.add(d); });
  Object.keys(D.cf || {}).forEach(d => { if ((D.cf[d] || []).length) { days.add(d); act.add(d); } });
  Object.keys(C).forEach(d => { act.add(d); if (C[d].w === true) days.add(d); else if (C[d].w === false) days.delete(d); });
  let ate = 0, miss = 0;
  dates7.forEach(d => Object.values((C[d] || {}).m || {}).forEach(v => { if (v === true) ate++; else if (v === false) miss++; }));
  const kgs = [...(D.meas || [])].filter(x => x.kg != null).sort((a, b) => a.date.localeCompare(b.date)), lk = kgs[kgs.length - 1];
  return { last: [...act].sort().pop() || null, w7: dates7.filter(d => days.has(d)).length, ate, miss, kg: lk ? lk.kg : null };
}

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
        if (same(hashPw(pw, u.salt), u.hash)) { if (u.disabled) return res.status(403).json({ error: "Bu hesap pasif. Koçunla iletişime geç." }); return res.json({ token: mkToken({ e: email, a: 0, v: u.hash.slice(0, 8) }), email, admin: false, name: u.name || "", surname: u.surname || "" }); }
      }
      return res.status(401).json({ error: "E-posta veya şifre hatalı" });
    }
    const u = readToken(req.headers.authorization);
    if (!u) return res.status(401).json({ error: "Oturum bitti, tekrar giriş yap" });
    if (!u.a) {
      const rr = await redis(["HGET", "users", u.e]), rc = rr && JSON.parse(rr);
      if (!rc || rc.disabled || u.v !== rc.hash.slice(0, 8)) return res.status(401).json({ error: "Oturum bitti, tekrar giriş yap" });
    }
    const key = "data:" + u.e;
    if (b.action === "loadx") { const x = await loadAll(u.e); return res.json({ core: x.core, months: x.months }); }
    if (b.action === "savex") {
      const mon = b.months || {};
      if (b.core !== undefined && b.core !== null) { const c = JSON.stringify(b.core); if (c.length > 900000) return res.status(413).json({ error: "Veri çok büyük" }); await redis(["SET", key, c]); }
      for (const [m, v] of Object.entries(mon)) {
        if (!/^\d{4}-\d{2}$/.test(m)) continue;
        if (v === null) { await redis(["HDEL", "mon:" + u.e, m]); continue; }
        const c = JSON.stringify(v); if (c.length > 900000) return res.status(413).json({ error: "Bir ayın verisi çok büyük" });
        await redis(["HSET", "mon:" + u.e, m, c]);
      }
      return res.json({ ok: true });
    }
    if (b.action === "mynote") return res.json({ note: pj(await redis(["GET", "note:" + u.e])) });
    if (b.action === "readnote") { const n = pj(await redis(["GET", "note:" + u.e])); if (n) { n.read = true; await redis(["SET", "note:" + u.e, JSON.stringify(n)]); } return res.json({ ok: true }); }
    if (b.action === "changepw") {
      if (u.a) return res.status(400).json({ error: "Yönetici şifresi Vercel'deki ADMIN_PASSWORD ayarından değiştirilir" });
      const np = String(b.password || "");
      if (np.length < 6) return res.status(400).json({ error: "Yeni şifre en az 6 karakter olmalı" });
      const rc = JSON.parse(await redis(["HGET", "users", u.e]));
      if (!same(hashPw(String(b.current || ""), rc.salt), rc.hash)) return res.status(400).json({ error: "Mevcut şifre hatalı" });
      const salt = crypto.randomBytes(16).toString("hex"), hash = hashPw(np, salt);
      await redis(["HSET", "users", u.e, JSON.stringify({ ...rc, salt, hash })]);
      return res.json({ ok: true, token: mkToken({ e: u.e, a: 0, v: hash.slice(0, 8) }) });
    }
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
    const ph = "photos:" + u.e, phr = "photos:" + (u.a && b.email ? String(b.email).trim().toLowerCase() : u.e);
    if (b.action === "photolist") return res.json({ dates: ((await redis(["HKEYS", phr])) || []).sort() });
    if (b.action === "photoget") return res.json({ img: (await redis(["HGET", phr, String(b.date || "")])) || null });
    if (b.action === "photodel") { await redis(["HDEL", ph, String(b.date || "")]); return res.json({ ok: true }); }
    if (b.action === "photoadd") {
      const d = String(b.date || ""), img = String(b.img || "");
      if (!/^\d{4}-\d{2}-\d{2}$/.test(d) || !img.startsWith("data:image/jpeg;base64,") || img.length > 450000) return res.status(400).json({ error: "Geçersiz fotoğraf" });
      const n = await redis(["HLEN", ph]), ex = await redis(["HEXISTS", ph, d]);
      if (n >= 40 && !ex) return res.status(400).json({ error: "En fazla 40 fotoğraf kaydedilebilir" });
      await redis(["HSET", ph, d, img]);
      return res.json({ ok: true });
    }
    if (b.action === "mydiet") { const d = await redis(["GET", "diet:" + u.e]); return res.json({ diet: d ? JSON.parse(d) : null }); }
    if (b.action === "myprogram") return res.json({ text: (await redis(["GET", "prog:" + u.e])) || "" });
    if (u.a) {
      const tg = String(b.email || "").trim().toLowerCase();
      if (b.action === "summary") {
        const today = /^\d{4}-\d{2}-\d{2}$/.test(String(b.today || "")) ? b.today : new Date().toISOString().slice(0, 10);
        const d0 = new Date(today + "T00:00:00Z"), day = n => { const t = new Date(d0); t.setUTCDate(t.getUTCDate() - n); return t.toISOString().slice(0, 10); };
        const dates7 = [0, 1, 2, 3, 4, 5, 6].map(day), a = (await redis(["HGETALL", "users"])) || [], list = [];
        for (let i = 0; i < a.length; i += 2) { const r = pj(a[i + 1]) || {}; list.push({ email: a[i], name: r.name || "", surname: r.surname || "", disabled: !!r.disabled }); }
        const out = await Promise.all(list.map(async m => {
          const [coreS, keys, noteS] = await Promise.all([redis(["GET", "data:" + m.email]), redis(["HKEYS", "mon:" + m.email]), redis(["GET", "note:" + m.email])]);
          const ks = (keys || []).sort(), want = new Set([today.slice(0, 7), day(7).slice(0, 7)]);
          if (ks.length) want.add(ks[ks.length - 1]);
          const months = {};
          await Promise.all([...want].filter(k => ks.includes(k)).map(async k => { const v = pj(await redis(["HGET", "mon:" + m.email, k])); if (v) months[k] = v; }));
          const note = pj(noteS);
          return { ...m, ...digest(mergeData(pj(coreS), months), dates7), note: note ? { read: !!note.read } : null };
        }));
        return res.json({ members: out });
      }
      if (b.action === "setnote" || b.action === "getnote") {
        if (tg !== AE && !(await redis(["HGET", "users", tg]))) return res.status(400).json({ error: "Bu kullanıcı yok" });
        if (b.action === "getnote") return res.json({ note: pj(await redis(["GET", "note:" + tg])) });
        const text = String(b.text || "").trim().slice(0, 600);
        if (text) await redis(["SET", "note:" + tg, JSON.stringify({ text, ts: Date.now(), read: false })]); else await redis(["DEL", "note:" + tg]);
        return res.json({ ok: true });
      }
      if (b.action === "setactive" || b.action === "deluser") {
        const rr = tg === AE ? null : await redis(["HGET", "users", tg]);
        if (tg === AE) return res.status(400).json({ error: "Yönetici hesabı değiştirilemez" });
        if (!rr) return res.status(400).json({ error: "Bu kullanıcı yok" });
        if (b.action === "setactive") { const r = JSON.parse(rr); r.disabled = !b.active; await redis(["HSET", "users", tg, JSON.stringify(r)]); return res.json({ ok: true }); }
        await redis(["HDEL", "users", tg]);
        await redis(["DEL", "data:" + tg, "mon:" + tg, "photos:" + tg, "prog:" + tg, "diet:" + tg, "note:" + tg]);
        return res.json({ ok: true });
      }
      if (b.action === "members") {
        const a = (await redis(["HGETALL", "users"])) || [], list = [];
        for (let i = 0; i < a.length; i += 2) { let r = {}; try { r = JSON.parse(a[i + 1]); } catch (e) {} list.push({ email: a[i], name: r.name || "", surname: r.surname || "", disabled: !!r.disabled }); }
        return res.json({ members: list });
      }
      if (b.action === "setpw") {
        const np = String(b.password || ""), rr = tg === AE ? null : await redis(["HGET", "users", tg]);
        if (tg === AE) return res.status(400).json({ error: "Yönetici şifresi Vercel'den değiştirilir" });
        if (!rr) return res.status(400).json({ error: "Bu kullanıcı yok" });
        if (np.length < 6) return res.status(400).json({ error: "Şifre en az 6 karakter olmalı" });
        const salt = crypto.randomBytes(16).toString("hex");
        await redis(["HSET", "users", tg, JSON.stringify({ ...JSON.parse(rr), salt, hash: hashPw(np, salt) })]);
        return res.json({ ok: true });
      }
      if (b.action === "memberdata") {
        if (tg !== AE && !(await redis(["HGET", "users", tg]))) return res.status(400).json({ error: "Bu kullanıcı yok" });
        const x = await loadAll(tg);
        return res.json({ data: x.core || Object.keys(x.months).length ? mergeData(x.core, x.months) : null });
      }
      if (b.action === "getdiet") { const d = await redis(["GET", "diet:" + tg]); return res.json({ diet: d ? JSON.parse(d) : null }); }
      if (b.action === "setdiet") {
        if (tg !== AE && !(await redis(["HGET", "users", tg]))) return res.status(400).json({ error: "Bu kullanıcı yok" });
        const x = b.diet || {}, num = v => Math.max(0, Math.min(20000, Math.round(+v || 0)));
        const n1 = v => Math.max(0, Math.min(99999, Math.round((+v || 0) * 10) / 10));
        const meals = (Array.isArray(x.meals) ? x.meals : []).slice(0, 12).map(m => ({
          name: String((m && m.name) || "Öğün").slice(0, 40),
          items: (Array.isArray(m && m.items) ? m.items : []).slice(0, 40).map(i => ({ n: String((i && i.n) || "").slice(0, 80), g: n1(i && i.g), ...(i && i.q ? { q: String(i.q).slice(0, 60) } : {}), kcal: Math.round(n1(i && i.kcal)), p: n1(i && i.p), c: n1(i && i.c), f: n1(i && i.f) })).filter(i => i.n)
        })).filter(m => m.items.length);
        const diet = { kcal: num(x.kcal), p: num(x.p), c: num(x.c), f: num(x.f), text: String(x.text || "").slice(0, 10000), meals };
        if (!diet.kcal && !diet.p && !diet.c && !diet.f && !diet.text.trim() && !meals.length) await redis(["DEL", "diet:" + tg]); else await redis(["SET", "diet:" + tg, JSON.stringify(diet)]);
        return res.json({ ok: true });
      }
      if (b.action === "getprogram") return res.json({ text: (await redis(["GET", "prog:" + String(b.email || "").trim().toLowerCase()])) || "" });
      if (b.action === "setprogram") {
        const t = String(b.email || "").trim().toLowerCase(), text = String(b.text || "");
        if (text.length > 20000) return res.status(400).json({ error: "Program çok uzun" });
        if (t !== AE && !(await redis(["HGET", "users", t]))) return res.status(400).json({ error: "Bu kullanıcı yok" });
        if (text.trim()) await redis(["SET", "prog:" + t, text]); else await redis(["DEL", "prog:" + t]);
        return res.json({ ok: true });
      }
      if (b.action === "users") return res.json({ users: await redis(["HKEYS", "users"]) });
      if (b.action === "adduser") {
        const email = String(b.email || "").trim().toLowerCase(), pw = String(b.password || ""), name = String(b.name || "").trim().slice(0, 40), surname = String(b.surname || "").trim().slice(0, 40);
        if (!/^\S+@\S+\.\S+$/.test(email)) return res.status(400).json({ error: "Geçerli bir e-posta yaz" });
        if (pw.length < 6) return res.status(400).json({ error: "Şifre en az 6 karakter olmalı" });
        if (email === AE) return res.status(400).json({ error: "Bu e-posta yönetici hesabı" });
        const salt = crypto.randomBytes(16).toString("hex");
        await redis(["HSET", "users", email, JSON.stringify({ salt, hash: hashPw(pw, salt), name, surname })]);
        return res.json({ ok: true });
      }
    }
    return res.status(400).json({ error: "Bilinmeyen işlem" });
  } catch (e) {
    return res.status(500).json({ error: "Sunucu hatası" });
  }
};

