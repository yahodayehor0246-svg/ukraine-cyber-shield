const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY;
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

app.disable("x-powered-by");
app.use(helmet());
app.use(cors({ origin: true, methods: ["GET", "POST"] }));
app.use(express.json({ limit: "10kb" }));
app.use(rateLimit({
  windowMs: 60 * 1000,
  limit: 60,
  standardHeaders: "draft-7",
  legacyHeaders: false
}));

async function initDb() {
  if (!process.env.DATABASE_URL) {
    throw new Error("DATABASE_URL is missing. Add a PostgreSQL database in Railway.");
  }
  await pool.query(`
    CREATE TABLE IF NOT EXISTS threat_reports (
      id BIGSERIAL PRIMARY KEY,
      url TEXT NOT NULL,
      domain TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'confirmed', 'rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `);
  await pool.query(`
    CREATE INDEX IF NOT EXISTS threat_reports_domain_status_idx
    ON threat_reports (domain, status)
  `);
}

function parseSafeUrl(input) {
  if (typeof input !== "string" || input.length > 2048) return null;
  try {
    const u = new URL(input.trim());
    if (!["http:", "https:"].includes(u.protocol)) return null;
    if (u.username || u.password) return null;
    const host = u.hostname.toLowerCase();
    if (!host || host === "localhost" || host.endsWith(".local")) return null;
    // Store only origin + path. Never retain query strings or fragments,
    // which can contain login tokens or personal data.
    const safeUrl = u.origin + u.pathname;
    return { url: safeUrl, domain: host, protocol: u.protocol };
  } catch {
    return null;
  }
}

function inspectUrl(parsed) {
  const flags = [];
  if (parsed.protocol !== "https:") flags.push("Сайт не використовує HTTPS");
  if (parsed.domain.startsWith("xn--") || parsed.domain.split(".").some(x => x.startsWith("xn--"))) {
    flags.push("Домен містить Punycode");
  }
  if (parsed.domain.split(".").length > 4) flags.push("Незвично довгий домен");
  if (/\\d{5,}/.test(parsed.domain)) flags.push("У домені є довга послідовність цифр");
  return {
    suspicious: flags.length > 0,
    flags,
    note: "Це лише автоматична евристична перевірка, а не гарантія безпеки."
  };
}

function requireAdmin(req, res, next) {
  if (!ADMIN_KEY) return res.status(503).json({ error: "ADMIN_KEY не налаштовано." });
  if (req.get("x-admin-key") !== ADMIN_KEY) {
    return res.status(401).json({ error: "Невірний ключ адміністратора." });
  }
  next();
}

app.get("/api/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ ok: true, service: "UKRAINE CYBER SHIELD API" });
  } catch {
    res.status(503).json({ ok: false, error: "База даних недоступна." });
  }
});

app.post("/api/check", async (req, res) => {
  const parsed = parseSafeUrl(req.body && req.body.url);
  if (!parsed) return res.status(400).json({ error: "Введи коректне повне HTTP або HTTPS посилання." });

  try {
    const found = await pool.query(
      "SELECT 1 FROM threat_reports WHERE domain = $1 AND status = 'confirmed' LIMIT 1",
      [parsed.domain]
    );
    const analysis = inspectUrl(parsed);
    res.json({
      url: parsed.url,
      domain: parsed.domain,
      confirmedThreat: found.rowCount > 0,
      status: found.rowCount > 0 ? "confirmed_threat" : (analysis.suspicious ? "suspicious_signs" : "no_obvious_signs"),
      flags: analysis.flags,
      note: analysis.note + " Відсутність попередження не означає, що сайт безпечний."
    });
  } catch {
    res.status(500).json({ error: "Не вдалося виконати перевірку." });
  }
});

app.post("/api/report", async (req, res) => {
  const parsed = parseSafeUrl(req.body && req.body.url);
  if (!parsed) return res.status(400).json({ error: "Некоректне посилання." });

  try {
    const existing = await pool.query(
      "SELECT id FROM threat_reports WHERE domain = $1 AND status = 'pending' LIMIT 1",
      [parsed.domain]
    );
    if (existing.rowCount) return res.json({ accepted: true, message: "Цей домен уже очікує перевірки." });

    const result = await pool.query(
      "INSERT INTO threat_reports (url, domain, status) VALUES ($1, $2, 'pending') RETURNING id",
      [parsed.url, parsed.domain]
    );
    res.status(201).json({ accepted: true, reportId: result.rows[0].id, message: "Повідомлення надіслано на перевірку." });
  } catch {
    res.status(500).json({ error: "Не вдалося зберегти повідомлення." });
  }
});

app.get("/api/threats", async (_req, res) => {
  try {
    const result = await pool.query(
      "SELECT DISTINCT domain FROM threat_reports WHERE status = 'confirmed' ORDER BY domain LIMIT 500"
    );
    res.json({ count: result.rowCount, domains: result.rows.map(row => row.domain) });
  } catch {
    res.status(500).json({ error: "Не вдалося отримати базу загроз." });
  }
});

// Admin-only review endpoints. Never trust user reports as confirmed automatically.
app.get("/api/admin/reports", requireAdmin, async (_req, res) => {
  const result = await pool.query(
    "SELECT id, url, domain, created_at FROM threat_reports WHERE status = 'pending' ORDER BY created_at ASC LIMIT 200"
  );
  res.json({ reports: result.rows });
});

app.post("/api/admin/reports/:id/decision", requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  const decision = req.body && req.body.decision;
  if (!Number.isSafeInteger(id) || id < 1 || !["confirmed", "rejected"].includes(decision)) {
    return res.status(400).json({ error: "Потрібні коректний ID та decision: confirmed або rejected." });
  }
  const result = await pool.query(
    "UPDATE threat_reports SET status = $1 WHERE id = $2 AND status = 'pending' RETURNING id, status",
    [decision, id]
  );
  if (!result.rowCount) return res.status(404).json({ error: "Очікуване повідомлення не знайдено." });
  res.json({ updated: result.rows[0] });
});

app.get("/", (_req, res) => {
  res.type("text").send("UKRAINE CYBER SHIELD API is running. Use /api/health.");
});

initDb().then(() => {
  app.listen(PORT, "0.0.0.0", () => console.log(`API listening on port ${PORT}`));
}).catch(err => {
  console.error("Startup failed:", err.message);
  process.exit(1);
});
