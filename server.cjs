require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const crypto = require("crypto");
const fetch = require("node-fetch");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(express.json());

// ==========================================
// 1. CORS — restrict to your domain
// ==========================================
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || "https://sg-chatbot-a2h.pages.dev").split(",").map(s => s.trim());
app.use(cors({
  origin: (origin, cb) => {
    // Allow requests with no origin (e.g. mobile apps, curl)
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error("Not allowed by CORS"));
  },
  credentials: true
}));

app.use(express.static("."));

// ==========================================
// 2. RATE LIMITING MIDDLEWARE (with cleanup)
// ==========================================
const rateLimit = {};

// Periodically clean up old entries to prevent memory leak
setInterval(() => {
  const now = Date.now();
  for (const ip in rateLimit) {
    rateLimit[ip] = rateLimit[ip].filter(t => now - t < 60000);
    if (rateLimit[ip].length === 0) delete rateLimit[ip];
  }
}, 5 * 60 * 1000); // Clean every 5 minutes

app.use((req, res, next) => {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  const now = Date.now();
  if (!rateLimit[ip]) rateLimit[ip] = [];
  rateLimit[ip] = rateLimit[ip].filter(t => now - t < 60000);
  if (rateLimit[ip].length >= 60) return res.status(429).send("Too many requests.");
  rateLimit[ip].push(now);
  next();
});

// ==========================================
// 3. MONGODB CONNECTION & SCHEMAS
// ==========================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("MongoDB connection error:", err));

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }, // bcrypt hash stored here
  role: { type: String, default: "user" },
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.model("User", UserSchema);

const BanSchema = new mongoose.Schema({
  ip: { type: String, required: true, unique: true },
  reason: { type: String, default: "Violation of terms" },
  createdAt: { type: Date, default: Date.now }
});
const Ban = mongoose.model("Ban", BanSchema);

// ==========================================
// 4. IP BAN MIDDLEWARE (Admin Bypass)
// ==========================================
app.use(async (req, res, next) => {
  if (req.path.startsWith("/api/admin")) {
    return next();
  }
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
  try {
    const banned = await Ban.findOne({ ip });
    if (banned) {
      return res.status(403).send("Access denied.");
    }
  } catch (err) {
    console.error("Ban check error:", err);
  }
  next();
});

// ==========================================
// 5. HELPER FUNCTIONS
// ==========================================

function sanitize(input) {
  if (typeof input === "string") return input.replace(/[\x00]/g, "").trim().slice(0, 2000);
  return input;
}

// JWT helpers
const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex");
const JWT_EXPIRY = "7d";

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

// Middleware to verify JWT on protected routes
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ success: false, error: "Authentication required" });
  }
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ success: false, error: "Invalid or expired token" });
  }
}

const GROQ_KEYS = (process.env.GROQ_API_KEYS || "").split(",").map(k => k.trim()).filter(Boolean);
const GOOGLE_MODELS = { "gemini-flash": "gemini-1.5-flash", "gemini-pro": "gemini-1.5-pro" };

async function callGoogle(model, messages) {
  const apiKey = process.env.GEMINI_API_KEY;
  const resp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${apiKey}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: messages.map(m => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] })) })
  });
  const data = await resp.json();
  return data?.candidates?.[0]?.content?.parts?.[0]?.text || "Error calling Google AI";
}

async function callMistral(model, messages) {
  const apiKey = process.env.MISTRAL_API_KEY;
  const resp = await fetch("https://api.mistral.ai/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
    body: JSON.stringify({ model, messages })
  });
  const data = await resp.json();
  return data?.choices?.[0]?.message?.content || "Error calling Mistral AI";
}

async function callOR(model, messages) {
  const apiKey = process.env.OR_API_KEY;
  const resp = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", "Authorization": `Bearer ${apiKey}` },
    body: JSON.stringify({ model, messages })
  });
  const data = await resp.json();
  return data?.choices?.[0]?.message?.content || "Error calling fallback AI";
}

async function callGroqRotating(model, messages) {
  for (const key of GROQ_KEYS) {
    try {
      const resp = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${key}` },
        body: JSON.stringify({ model, messages })
      });
      if (resp.status === 429) continue;
      if (!resp.ok) continue;
      const data = await resp.json();
      return data?.choices?.[0]?.message?.content || "Error";
    } catch (e) {
      continue;
    }
  }
  return "All Groq keys rate limited or failed.";
}

async function tryGroqStream(messages, model, res) {
  for (const key of GROQ_KEYS) {
    try {
      const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST",
        headers: { "Content-Type": "application/json", "Authorization": `Bearer ${key}` },
        body: JSON.stringify({ model, messages, stream: true })
      });
      if (r.status === 429) continue;
      if (!r.ok) continue;

      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");

      r.body.on("data", chunk => res.write(chunk));
      r.body.on("end", () => res.end());
      return true;
    } catch (e) {
      continue;
    }
  }
  return false;
}

// Admin secret verification helper
function verifyAdminSecret(secret) {
  const adminSecret = process.env.ADMIN_SECRET;
  if (!secret || !adminSecret) return false;
  try {
    if (secret.length !== adminSecret.length) return false;
    return crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(adminSecret));
  } catch {
    return false;
  }
}

// ==========================================
// 6. ADMIN ROUTES
// ==========================================
app.post("/api/admin/verify", (req, res) => {
  const { secret } = req.body;
  if (!verifyAdminSecret(secret)) return res.status(401).json({ success: false, error: "Wrong secret" });
  res.json({ success: true });
});

app.post("/api/admin/ban", async (req, res) => {
  const { secret, ip, reason } = req.body;
  if (!verifyAdminSecret(secret)) return res.status(401).json({ success: false, error: "Unauthorized" });
  try {
    await Ban.findOneAndUpdate({ ip }, { ip, reason }, { upsert: true, returnDocument: "after" });
    res.json({ success: true, message: "IP banned successfully" });
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to ban IP" });
  }
});

app.post("/api/admin/unban", async (req, res) => {
  const { secret, ip } = req.body;
  if (!verifyAdminSecret(secret)) return res.status(401).json({ success: false, error: "Unauthorized" });
  try {
    await Ban.deleteOne({ ip });
    res.json({ success: true, message: "IP unbanned successfully" });
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to unban IP" });
  }
});

app.post("/api/admin/banned-ips", async (req, res) => {
  const { secret } = req.body;
  if (!verifyAdminSecret(secret)) return res.status(401).json({ success: false, error: "Unauthorized" });
  try {
    const list = await Ban.find({});
    res.json({ success: true, banned: list });
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to fetch list" });
  }
});

// ==========================================
// 7. AUTHENTICATION ROUTES
// ==========================================
app.post("/signup", async (req, res) => {
  const email = sanitize(req.body.email);
  const password = sanitize(req.body.password);
  if (!email || !password) return res.status(400).json({ success: false, error: "All fields required" });
  if (password.length < 8) return res.status(400).json({ success: false, error: "Password must be at least 8 characters" });
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ success: false, error: "User already exists" });
    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ email, password: hashed });
    const token = signToken({ userId: user._id, email: user.email, role: user.role });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, error: "Signup failed" });
  }
});

app.post("/login", async (req, res) => {
  const email = sanitize(req.body.email);
  const password = sanitize(req.body.password);
  if (!email || !password) return res.status(400).json({ success: false, error: "All fields required" });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ success: false, error: "Invalid email or password" });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ success: false, error: "Invalid email or password" });
    const token = signToken({ userId: user._id, email: user.email, role: user.role });
    res.json({ success: true, token });
  } catch (err) {
    res.status(500).json({ success: false, error: "Login failed" });
  }
});

app.post("/settings/change-password", requireAuth, async (req, res) => {
  const oldPassword = sanitize(req.body.oldPassword);
  const newPassword = sanitize(req.body.newPassword);
  if (!oldPassword || !newPassword) return res.status(400).json({ success: false, error: "All fields required" });
  if (newPassword.length < 8) return res.status(400).json({ success: false, error: "New password must be at least 8 characters" });
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ success: false, error: "User not found" });
    const valid = await bcrypt.compare(oldPassword, user.password);
    if (!valid) return res.status(401).json({ success: false, error: "Current password is incorrect" });
    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    res.json({ success: true, message: "Password updated" });
  } catch (err) {
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ==========================================
// 8. CHAT & STREAMING ROUTES
// ==========================================
app.post("/chat", requireAuth, async (req, res) => {
  const { messages, model, modelKey } = req.body;
  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ success: false, error: "messages must be a non-empty array" });
  }
  try {
    if (modelKey && GOOGLE_MODELS[modelKey]) {
      const text = await callGoogle(GOOGLE_MODELS[modelKey], messages);
      return res.json({ response: text });
    }
    if (modelKey && modelKey.startsWith("mistral")) {
      const text = await callMistral(model, messages);
      return res.json({ response: text });
    }
    if (modelKey === "or") {
      const text = await callOR(model, messages);
      return res.json({ response: text });
    }
    const text = await callGroqRotating(model, messages);
    res.json({ response: text });
  } catch (err) {
    res.status(500).json({ success: false, error: "Chat failed" });
  }
});

app.post("/chat/stream", requireAuth, async (req, res) => {
  const { messages, model, modelKey } = req.body;
  if (!Array.isArray(messages) || messages.length === 0) {
    return res.status(400).json({ success: false, error: "messages must be a non-empty array" });
  }
  try {
    const success = await tryGroqStream(messages, model, res);

    if (!success) {
      // Set SSE headers before writing fallback data
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");

      if (modelKey && GOOGLE_MODELS[modelKey]) {
        const text = await callGoogle(GOOGLE_MODELS[modelKey], messages);
        res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: text } }] })}\n\n`);
        res.end();
      } else if (modelKey && modelKey.startsWith("mistral")) {
        const text = await callMistral(model, messages);
        res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: text } }] })}\n\n`);
        res.end();
      } else {
        res.write(`data: ${JSON.stringify({ error: "Streaming failed across all channels." })}\n\n`);
        res.end();
      }
    }
  } catch (err) {
    if (!res.writableEnded) res.status(500).send("Stream error");
  }
});

// ==========================================
// 9. SERVER START
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
