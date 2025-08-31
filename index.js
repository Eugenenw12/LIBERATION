// index.js
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import http from "http";
import { Server as SocketIOServer } from "socket.io";
import pg from "pg";

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: { origin: "*", methods: ["GET", "POST"] },
});

app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-render";

// ---- PostgreSQL
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// ---- Ensure tables exist
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
  `);
  console.log("✅ DB ready");
}
initDb().catch(console.error);

// ---- Auth helper
function auth(req, res, next) {
  const hdr = req.headers.authorization || "";
  const token = hdr.startsWith("Bearer ") ? hdr.slice(7) : null;
  if (!token) return res.status(401).json({ error: "missing token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET); // { uid }
    next();
  } catch {
    return res.status(401).json({ error: "invalid token" });
  }
}

// ---- Routes
app.get("/", (_req, res) =>
  res.send("Liberation backend + Postgres is running 🚀")
);

app.get("/health/db", async (_req, res) => {
  try {
    const r = await pool.query("SELECT NOW() as now");
    res.json({ ok: true, now: r.rows[0].now });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// SIGN UP
app.post("/auth/register", async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password)
      return res.status(400).json({ error: "phone & password required" });

    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      "INSERT INTO users (phone, password_hash) VALUES ($1, $2) RETURNING id, phone, created_at",
      [phone, hash]
    );
    const user = rows[0];
    const token = jwt.sign({ uid: user.id }, JWT_SECRET);
    res.json({ user, token });
  } catch (e) {
    if (String(e).includes("duplicate"))
      return res.status(409).json({ error: "phone already registered" });
    res.status(500).json({ error: "server error" });
  }
});

// LOGIN
app.post("/auth/login", async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password)
      return res.status(400).json({ error: "phone & password required" });

    const { rows } = await pool.query(
      "SELECT * FROM users WHERE phone=$1",
      [phone]
    );
    const user = rows[0];
    if (!user) return res.status(401).json({ error: "invalid credentials" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "invalid credentials" });

    const token = jwt.sign({ uid: user.id }, JWT_SECRET);
    res.json({ user: { id: user.id, phone: user.phone }, token });
  } catch {
    res.status(500).json({ error: "server error" });
  }
});

// WHO AM I
app.get("/auth/me", auth, async (req, res) => {
  const { rows } = await pool.query(
    "SELECT id, phone, created_at FROM users WHERE id=$1",
    [req.user.uid]
  );
  res.json(rows[0] || null);
});

// SEND MESSAGE
app.post("/messages", auth, async (req, res) => {
  const { text } = req.body;
  if (!text) return res.status(400).json({ error: "text required" });

  const { rows } = await pool.query(
    "INSERT INTO messages (sender_id, text) VALUES ($1, $2) RETURNING id, sender_id, text, created_at",
    [req.user.uid, text]
  );
  const message = rows[0];

  // broadcast for realtime clients (optional)
  io.emit("message", message);

  res.json(message);
});

// LIST MESSAGES (optionally since=ISO date)
app.get("/messages", auth, async (req, res) => {
  const since = req.query.since;
  const q = since
    ? {
        text: `
          SELECT m.*, u.phone AS sender_phone
          FROM messages m
          JOIN users u ON u.id=m.sender_id
          WHERE m.created_at > $1
          ORDER BY m.created_at ASC`,
        params: [since],
      }
    : {
        text: `
          SELECT m.*, u.phone AS sender_phone
          FROM messages m
          JOIN users u ON u.id=m.sender_id
          ORDER BY m.created_at ASC`,
        params: [],
      };

  const { rows } = await pool.query(q.text, q.params);
  res.json(rows);
});

// ---- Socket.IO basic hookup
io.on("connection", (socket) => {
  console.log("🔌 client connected", socket.id);
  socket.on("disconnect", () => console.log("❌ client disconnected", socket.id));
});

// ---- Start
server.listen(PORT, () => console.log(`Server running on ${PORT}`));
