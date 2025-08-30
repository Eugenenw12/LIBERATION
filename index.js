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
const JWT_SECRET = process.env.JWT_SECRET || "change-me";

// ---- PostgreSQL
const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false,
});

// Ensure tables exist
async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      phone TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  await pool.query(`
    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INT REFERENCES users(id),
      content TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
}
initDb().catch(console.error);

// ---- Routes
app.get("/", (_req, res) => res.send("Liberation backend is running 🚀"));

app.post("/auth/register", async (req, res) => {
  try {
    const { phone, password } = req.body;
    if (!phone || !password) return res.status(400).json({ error: "phone & password required" });
    const hash = await bcrypt.hash(password, 10);
    const { rows } = await pool.query(
      "INSERT INTO users (phone, password_hash) VALUES ($1, $2) RETURNING id, phone",
      [phone, hash]
    );
    const user = rows[0];
    const token = jwt.sign({ uid: user.id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ user, token });
  } catch (e) {
    if (String(e).includes("duplicate")) return res.status(409).json({ error: "phone already registered" });
    res.status(500).json({ error: "server error" });
  }
});

app.post("/auth/login", async (req, res) => {
  const { phone, password } = req.body;
  if (!phone || !password) return res.status(400).json({ error: "phone & password required" });
  const { rows } = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
  const user = rows[0];
  if (!user) return res.status(401).json({ error: "invalid credentials" });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: "invalid credentials" });
  const token = jwt.sign({ uid: user.id }, JWT_SECRET, { expiresIn: "7d" });
  res.json({ user: { id: user.id, phone: user.phone }, token });
});

// auth helper
function verify(token) {
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

// ---- Socket.IO (simple global chat)
io.on("connection", (socket) => {
  socket.on("join", ({ token }) => {
    const payload = verify(token);
    if (!payload) return socket.emit("error", "auth failed");
    socket.data.uid = payload.uid;
    socket.join("global");
    socket.emit("joined");
  });

  socket.on("message", async ({ content }) => {
    if (!socket.data.uid) return socket.emit("error", "not joined");
    const { rows } = await pool.query(
      "INSERT INTO messages (sender_id, content) VALUES ($1,$2) RETURNING id, sender_id, content, created_at",
      [socket.data.uid, content]
    );
    io.to("global").emit("message", rows[0]);
  });
});

server.listen(PORT, () => console.log(`Server live on ${PORT}`));
