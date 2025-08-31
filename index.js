
// index.js (production baseline)
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import pg from "pg";
import crypto from "crypto";
import { z } from "zod";

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

const PORT = process.env.PORT || 3000;
const ACCESS_SECRET  = process.env.JWT_ACCESS_SECRET  || process.env.JWT_SECRET || "dev-access";
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || "dev-refresh";
const CORS_ORIGIN = process.env.CORS_ORIGIN || "*";

app.use(helmet());
app.use(express.json());

// CORS: open for now; later set CORS_ORIGIN to your frontend URL
if (CORS_ORIGIN === "*") app.use(cors());
else app.use(cors({ origin: CORS_ORIGIN, credentials: true }));

// Rate limits
const authLimiter = rateLimit({ windowMs: 15*60*1000, max: 100, standardHeaders: true, legacyHeaders: false });
const apiLimiter  = rateLimit({ windowMs: 60*1000,    max: 600, standardHeaders: true, legacyHeaders: false });
app.use("/auth", authLimiter);
app.use(apiLimiter);

// Postgres
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Ensure schema
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
  console.log("✅ DB ready");
}
initDb().catch((e) => { console.error(e); process.exit(1); });

// Helpers
const RegisterSchema = z.object({
  phone: z.string().min(3).max(30),
  password: z.string().min(6).max(50),
});
const AccessAuth = (req, res, next) => {
  const h = req.headers.authorization || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: "missing token" });
  try { req.user = jwt.verify(token, ACCESS_SECRET); next(); }
  catch { return res.status(401).json({ error: "invalid/expired token" }); }
};
const signAccess  = (uid) => jwt.sign({ uid }, ACCESS_SECRET, { expiresIn: "15m" });
const signRefresh = (uid) => jwt.sign({ uid, typ: "refresh" }, REFRESH_SECRET, { expiresIn: "30d" });
const hashToken   = (t) => crypto.createHash("sha256").update(t).digest("hex");
async function storeRefresh(uid, tok) {
  await pool.query(
    `INSERT INTO refresh_tokens (user_id, token_hash)
     VALUES ($1,$2)
     ON CONFLICT (user_id) DO UPDATE SET token_hash=EXCLUDED.token_hash, created_at=NOW()`,
    [uid, hashToken(tok)]
  );
}
async function refreshMatches(uid, tok) {
  const { rows } = await pool.query("SELECT token_hash FROM refresh_tokens WHERE user_id=$1", [uid]);
  return rows[0]?.token_hash === hashToken(tok);
}

// Routes
app.get("/", (_req, res) => res.send("Liberation backend (secure) is running 🚀"));
app.get("/health/db", async (_req, res) => {
  try { const r = await pool.query("SELECT NOW() as now"); res.json({ ok: true, now: r.rows[0].now }); }
  catch (e) { res.status(500).json({ ok: false, error: e.message }); }
});

// Register
app.post("/auth/register", async (req, res) => {
  try {
    const { phone, password } = RegisterSchema.parse(req.body || {});
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      "INSERT INTO users (phone, password_hash) VALUES ($1, $2) RETURNING id, phone, created_at",
      [phone, hash]
    );
    const user = rows[0];
    const accessToken  = signAccess(user.id);
    const refreshToken = signRefresh(user.id);
    await storeRefresh(user.id, refreshToken);
    res.status(201).json({ user, accessToken, refreshToken });
  } catch (e) {
    if (e.code === "23505" || String(e).includes("duplicate")) return res.status(409).json({ error: "phone already registered" });
    if (e.errors) return res.status(400).json({ error: "invalid input", details: e.errors });
    res.status(500).json({ error: "server error" });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  try {
    const { phone, password } = RegisterSchema.parse(req.body || {});
    const { rows } = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "invalid credentials" });
    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "invalid credentials" });
    const accessToken  = signAccess(user.id);
    const refreshToken = signRefresh(user.id);
    await storeRefresh(user.id, refreshToken);
    res.json({ user: { id: user.id, phone: user.phone, created_at: user.created_at }, accessToken, refreshToken });
  } catch (e) {
    if (e.errors) return res.status(400).json({ error: "invalid input", details: e.errors });
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
    const newAccess  = signAccess(payload.uid);
    const newRefresh = signRefresh(payload.uid);
    await storeRefresh(payload.uid, newRefresh);
    res.json({ accessToken: newAccess, refreshToken: newRefresh });
  } catch {
    res.status(401).json({ error: "invalid/expired refresh" });
  }
});

// Logout (invalidate refresh)
app.post("/auth/logout", AccessAuth, async (req, res) => {
  await pool.query("DELETE FROM refresh_tokens WHERE user_id=$1", [req.user.uid]);
  res.json({ ok: true });
});

// Me
app.get("/auth/me", AccessAuth, async (req, res) => {
  const { rows } = await pool.query("SELECT id, phone, created_at FROM users WHERE id=$1", [req.user.uid]);
  res.json(rows[0] || null);
});

// Messaging
app.post("/messages", AccessAuth, async (req, res) => {
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

app.get("/messages", AccessAuth, async (_req, res) => {
  const { rows } = await pool.query(`
    SELECT m.*, u.phone AS sender_phone
    FROM messages m
    JOIN users u ON u.id = m.sender_id
    ORDER BY m.created_at ASC
  `);
  res.json(rows);
});

// Socket.IO
io.on("connection", (socket) => {
  console.log("🔌 client connected", socket.id);
  socket.on("disconnect", () => console.log("❌ client disconnected", socket.id));
});

server.listen(PORT, () => console.log(`Server running on ${PORT}`));
