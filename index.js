// index.js — production-ready, aligned with your package.json

import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import { Pool } from "pg";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import { z } from "zod";

/* ---------- Config ---------- */
const PORT = process.env.PORT || 3000;
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";
const ACCESS_SECRET = process.env.ACCESS_SECRET || "dev-access";
const REFRESH_SECRET = process.env.REFRESH_SECRET || "dev-refresh";

/* ---------- Database ---------- */
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }, // required for Render Postgres
});

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
      text TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id SERIAL PRIMARY KEY,
      user_id INTEGER UNIQUE REFERENCES users(id) ON DELETE CASCADE,
      token_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_id);
  `);
  console.log("✅ Database schema ready");
}
initDb().catch((e) => {
  console.error("DB init error:", e);
  process.exit(1);
});

/* ---------- App / Server / Socket ---------- */
const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: { origin: CORS_ORIGIN, methods: ["GET", "POST", "PUT", "PATCH", "DELETE"] },
});

app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({ origin: CORS_ORIGIN, credentials: true }));
app.use(express.json({ limit: "1mb" }));

// Rate limits
app.use(
  rateLimit({
    windowMs: 60 * 1000,
    limit: 600,
    standardHeaders: true,
    legacyHeaders: false,
  })
);
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/auth", authLimiter);

/* ---------- Helpers ---------- */
const Credentials = z.object({
  phone: z.string().min(3).max(30),
  password: z.string().min(6).max(128),
});

function signAccess(uid) {
  return jwt.sign({ uid }, ACCESS_SECRET, { expiresIn: "15m" });
}
function signRefresh(uid) {
  return jwt.sign({ uid, typ: "refresh" }, REFRESH_SECRET, { expiresIn: "30d" });
}
const sha256 = (s) => crypto.createHash("sha256").update(s).digest("hex");

async function storeRefresh(userId, rawToken) {
  const tokenHash = sha256(rawToken);
  await pool.query(
    `INSERT INTO refresh_tokens (user_id, token_hash)
     VALUES ($1,$2)
     ON CONFLICT (user_id) DO UPDATE SET token_hash = EXCLUDED.token_hash, created_at = NOW()`,
    [userId, tokenHash]
  );
}
async function refreshMatches(userId, rawToken) {
  const { rows } = await pool.query("SELECT token_hash FROM refresh_tokens WHERE user_id=$1", [userId]);
  return rows[0]?.token_hash === sha256(rawToken);
}

function auth(req, res, next) {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "missing token" });
  try {
    req.user = jwt.verify(token, ACCESS_SECRET); // { uid }
    next();
  } catch {
    return res.status(401).json({ error: "invalid/expired token" });
  }
}

/* ---------- Health ---------- */
app.get("/", (_req, res) => res.send("OK"));
app.get("/health", async (_req, res) => {
  try {
    const r = await pool.query("SELECT 1 AS ok");
    res.json({ ok: true, db: r.rows?.[0]?.ok === 1 });
  } catch (e) {
    res.status(500).json({ ok: false, db: false, error: String(e?.message || e) });
  }
});

/* ---------- Auth ---------- */
// Register
app.post("/auth/register", async (req, res) => {
  try {
    const { phone, password } = Credentials.parse(req.body || {});
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      "INSERT INTO users (phone, password_hash) VALUES ($1, $2) RETURNING id, phone, created_at",
      [phone, hash]
    );
    const user = rows[0];
    const accessToken = signAccess(user.id);
    const refreshToken = signRefresh(user.id);
    await storeRefresh(user.id, refreshToken);
    res.status(201).json({ user, accessToken, refreshToken });
  } catch (e) {
    if (e?.code === "23505" || String(e).includes("duplicate"))
      return res.status(409).json({ error: "phone already registered" });
    if (e?.errors) return res.status(400).json({ error: "invalid input" });
    res.status(500).json({ error: "server error" });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  try {
    const { phone, password } = Credentials.parse(req.body || {});
    const { rows } = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "invalid credentials" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "invalid credentials" });
    const accessToken = signAccess(user.id);
    const refreshToken = signRefresh(user.id);
    await storeRefresh(user.id, refreshToken);
    res.json({ user: { id: user.id, phone: user.phone, created_at: user.created_at }, accessToken, refreshToken });
  } catch (e) {
    if (e?.errors) return res.status(400).json({ error: "invalid input" });
    res.status(500).json({ error: "server error" });
  }
});

// Refresh (rotate)
app.post("/auth/refresh", async (req, res) => {
  try {
    const { refreshToken } = req.body || {};
    if (!refreshToken) return res.status(400).json({ error: "refreshToken required" });
    const payload = jwt.verify(refreshToken, REFRESH_SECRET); // { uid, typ }
    if (payload.typ !== "refresh") return res.status(400).json({ error: "not a refresh token" });
    const valid = await refreshMatches(payload.uid, refreshToken);
    if (!valid) return res.status(401).json({ error: "refresh invalidated" });
    const newAccess = signAccess(payload.uid);
    const newRefresh = signRefresh(payload.uid);
    await storeRefresh(payload.uid, newRefresh);
    res.json({ accessToken: newAccess, refreshToken: newRefresh });
  } catch {
    res.status(401).json({ error: "invalid/expired refresh" });
  }
});

// Logout (invalidate refresh)
app.post("/auth/logout", auth, async (req, res) => {
  await pool.query("DELETE FROM refresh_tokens WHERE user_id=$1", [req.user.uid]);
  res.json({ ok: true });
});

// Me
app.get("/auth/me", auth, async (req, res) => {
  const { rows } = await pool.query("SELECT id, phone, created_at FROM users WHERE id=$1", [req.user.uid]);
  res.json(rows[0] || null);
});

/* ---------- Messaging ---------- */
app.post("/messages", auth, async (req, res) => {
  const text = (req.body?.text || "").trim();
  if (!text) return res.status(400).json({ error: "text required" });
  const { rows } = await pool.query(
    "INSERT INTO messages (sender_id, text) VALUES ($1, $2) RETURNING id, sender_id, text, created_at",
    [req.user.uid, text]
  );
  const message = rows[0];
  io.emit("message", message);
  res.status(201).json(message);
});

app.get("/messages", auth, async (_req, res) => {
  const { rows } = await pool.query(`
    SELECT m.*, u.phone AS sender_phone
    FROM messages m
    JOIN users u ON u.id = m.sender_id
    ORDER BY m.created_at ASC
  `);
  res.json(rows);
});

/* ---------- 404 + Error handlers ---------- */
app.use((_req, res) => res.status(404).json({ error: "Not Found" }));
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

/* ---------- Socket.IO ---------- */
io.on("connection", (socket) => {
  console.log("🔌 socket connected:", socket.id);
  socket.on("disconnect", () => console.log("❌ socket disconnected:", socket.id));
});

/* ---------- Start ---------- */
server.listen(PORT, () => {
  console.log(`Server listening on :${PORT}`);
});
