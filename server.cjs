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
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    cb(new Error("Not allowed by CORS"));
  },
  credentials: true
}));
app.use(express.static("."));

// ==========================================
// 2. RATE LIMITING (with memory cleanup)
// ==========================================
const rateLimit = {};
setInterval(() => {
  const now = Date.now();
  for (const ip in rateLimit) {
    rateLimit[ip] = rateLimit[ip].filter(t => now - t < 60000);
    if (rateLimit[ip].length === 0) delete rateLimit[ip];
  }
}, 5 * 60 * 1000);

app.use((req, res, next) => {
  const ip = req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.socket.remoteAddress;
  const now = Date.now();
  if (!rateLimit[ip]) rateLimit[ip] = [];
  rateLimit[ip] = rateLimit[ip].filter(t => now - t < 60000);
  if (rateLimit[ip].length >= 60) return res.status(429).send("Too many requests.");
  rateLimit[ip].push(now);
  next();
});

// ==========================================
// 3. MONGODB SCHEMAS
// ==========================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ Connected to MongoDB"))
  .catch(err => console.error("MongoDB error:", err));

const UserSchema = new mongoose.Schema({
  email:        { type: String, required: true, unique: true },
  password:     { type: String, required: true },
  displayName:  { type: String, default: "" },
  plan:         { type: String, default: "free" },
  proExpiresAt: { type: Date, default: null },
  isBlocked:    { type: Boolean, default: false },
  blockReason:  { type: String, default: "" },
  lastLoginAt:  { type: Date, default: null },
  lastLoginIP:  { type: String, default: "" },
  totalMessages:{ type: Number, default: 0 },
  role:         { type: String, default: "user" },
  createdAt:    { type: Date, default: Date.now }
});
const User = mongoose.model("User", UserSchema);

const PaymentSchema = new mongoose.Schema({
  email:         { type: String, required: true },
  method:        { type: String, required: true },
  transactionId: { type: String, required: true },
  amount:        { type: Number, required: true },
  plan:          { type: String, required: true },
  status:        { type: String, default: "pending" }, // pending | approved | rejected
  createdAt:     { type: Date, default: Date.now }
});
const Payment = mongoose.model("Payment", PaymentSchema);

const BanSchema = new mongoose.Schema({
  ip:        { type: String, required: true, unique: true },
  reason:    { type: String, default: "Violation of terms" },
  blockedBy: { type: String, default: "admin" },   // admin | auto
  expiresAt: { type: Date, default: null },         // null = permanent
  createdAt: { type: Date, default: Date.now }
});
const Ban = mongoose.model("Ban", BanSchema);

const SecurityLogSchema = new mongoose.Schema({
  type:      { type: String, required: true },
  severity:  { type: String, default: "medium" }, // low | medium | high | critical
  ip:        { type: String, default: "" },
  details:   { type: mongoose.Schema.Types.Mixed, default: {} },
  resolved:  { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});
const SecurityLog = mongoose.model("SecurityLog", SecurityLogSchema);

// ==========================================
// 4. IP BAN MIDDLEWARE
//    → ADMIN_IP in .env = your IP, never blocked
// ==========================================
const ADMIN_IP_WHITELIST = (process.env.ADMIN_IP || "").split(",").map(s => s.trim()).filter(Boolean);

app.use(async (req, res, next) => {
  // Admin routes always pass through
  if (req.path.startsWith("/admin")) return next();

  const ip = req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.socket.remoteAddress;

  // Your whitelisted IP(s) are NEVER blocked
  if (ADMIN_IP_WHITELIST.length && ADMIN_IP_WHITELIST.includes(ip)) return next();

  try {
    const now = new Date();
    // Auto-clear expired bans
    await Ban.deleteMany({ expiresAt: { $lte: now, $ne: null } });

    const banned = await Ban.findOne({ ip });
    if (banned) {
      await SecurityLog.create({ type: "BLOCKED_IP_HIT", severity: "high", ip, details: { reason: banned.reason } });
      return res.status(403).json({ error: "Access denied. Your IP is blocked." });
    }
  } catch (err) {
    console.error("Ban check error:", err);
  }
  next();
});

// ==========================================
// 5. HELPERS
// ==========================================
function sanitize(input) {
  if (typeof input === "string") return input.replace(/[\x00]/g, "").trim().slice(0, 2000);
  return input;
}

function getIP(req) {
  return req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.socket.remoteAddress;
}

const JWT_SECRET = process.env.JWT_SECRET || crypto.randomBytes(64).toString("hex");
const JWT_EXPIRY = "7d";

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: JWT_EXPIRY });
}

function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth?.startsWith("Bearer ")) return res.status(401).json({ error: "Authentication required" });
  try {
    req.user = jwt.verify(auth.slice(7), JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid or expired token" });
  }
}

// ── Admin secret verification ──
const ADMIN_SECRET = process.env.ADMIN_SECRET || "";

function verifyAdmin(req, res) {
  // Accept secret from header OR body
  const secret = req.headers["x-admin-secret"] || req.body?.secret || "";
  if (!secret || !ADMIN_SECRET) { res.status(401).json({ error: "Unauthorized" }); return false; }
  try {
    if (secret.length !== ADMIN_SECRET.length) { res.status(401).json({ error: "Unauthorized" }); return false; }
    if (!crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(ADMIN_SECRET))) {
      SecurityLog.create({ type: "ADMIN_AUTH_FAIL", severity: "high", ip: getIP(req), details: { path: req.path } }).catch(()=>{});
      res.status(401).json({ error: "Unauthorized" }); return false;
    }
  } catch { res.status(401).json({ error: "Unauthorized" }); return false; }
  return true;
}

// ── AI provider helpers ──
const GROQ_KEYS = (process.env.GROQ_API_KEYS || "").split(",").map(k => k.trim()).filter(Boolean);
const GOOGLE_MODELS = { "gemini-flash": "gemini-1.5-flash", "gemini-pro": "gemini-1.5-pro" };

async function callGoogle(model, messages) {
  const resp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: messages.map(m => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: m.content }] })) })
  });
  const data = await resp.json();
  return data?.candidates?.[0]?.content?.parts?.[0]?.text || "Error calling Google AI";
}

async function callMistral(model, messages) {
  const resp = await fetch("https://api.mistral.ai/v1/chat/completions", {
    method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Bearer ${process.env.MISTRAL_API_KEY}` },
    body: JSON.stringify({ model, messages })
  });
  const data = await resp.json();
  return data?.choices?.[0]?.message?.content || "Error calling Mistral AI";
}

async function callOR(model, messages) {
  const resp = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Bearer ${process.env.OR_API_KEY}` },
    body: JSON.stringify({ model, messages })
  });
  const data = await resp.json();
  return data?.choices?.[0]?.message?.content || "Error calling fallback AI";
}

async function callGroqRotating(model, messages) {
  for (const key of GROQ_KEYS) {
    try {
      const resp = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Bearer ${key}` },
        body: JSON.stringify({ model, messages })
      });
      if (resp.status === 429 || !resp.ok) continue;
      const data = await resp.json();
      return data?.choices?.[0]?.message?.content || "Error";
    } catch { continue; }
  }
  return "All Groq keys rate limited or failed.";
}

async function tryGroqStream(messages, model, res) {
  for (const key of GROQ_KEYS) {
    try {
      const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Bearer ${key}` },
        body: JSON.stringify({ model, messages, stream: true })
      });
      if (r.status === 429 || !r.ok) continue;
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");
      r.body.on("data", chunk => res.write(chunk));
      r.body.on("end", () => res.end());
      return true;
    } catch { continue; }
  }
  return false;
}

// ==========================================
// 6. ADMIN — STATS
// ==========================================
app.get("/admin/stats", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const now = new Date();
    const todayStart = new Date(now); todayStart.setHours(0,0,0,0);
    const weekAgo = new Date(now - 7*24*60*60*1000);
    const sixMonthsAgo = new Date(now); sixMonthsAgo.setMonth(sixMonthsAgo.getMonth() - 6);

    const [total, pro, blocked, pendingPayments, totalPaymentsData, unresolvedLogs, critical, newToday,
           signupsByDay, monthlyRevenue] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ plan:"pro", proExpiresAt:{ $gt: now } }),
      User.countDocuments({ isBlocked: true }),
      Payment.countDocuments({ status:"pending" }),
      Payment.aggregate([{ $match:{ status:"approved" } }, { $group:{ _id:null, total:{ $sum:"$amount" }, count:{ $sum:1 } } }]),
      SecurityLog.countDocuments({ resolved: false }),
      SecurityLog.countDocuments({ resolved: false, severity: "critical" }),
      User.countDocuments({ createdAt:{ $gte: todayStart } }),
      User.aggregate([
        { $match:{ createdAt:{ $gte: weekAgo } } },
        { $group:{ _id:{ $dateToString:{ format:"%m/%d", date:"$createdAt" } }, count:{ $sum:1 } } },
        { $sort:{ _id:1 } }
      ]),
      Payment.aggregate([
        { $match:{ status:"approved", createdAt:{ $gte: sixMonthsAgo } } },
        { $group:{ _id:{ y:{ $year:"$createdAt" }, m:{ $month:"$createdAt" } }, revenue:{ $sum:"$amount" }, count:{ $sum:1 } } },
        { $sort:{ "_id.y":1, "_id.m":1 } }
      ])
    ]);

    res.json({
      total, pro, blocked, pendingPayments,
      revenue: totalPaymentsData[0]?.total || 0,
      totalPayments: totalPaymentsData[0]?.count || 0,
      unresolved: unresolvedLogs, critical, newToday,
      signupsByDay, monthlyRevenue
    });
  } catch(err) { res.status(500).json({ error: "Stats fetch failed" }); }
});

// ==========================================
// 7. ADMIN — PAYMENTS
// ==========================================
app.get("/admin/payments", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const payments = await Payment.find().sort({ createdAt: -1 }).limit(200);
    res.json(payments);
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/approve/:id", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const payment = await Payment.findByIdAndUpdate(req.params.id, { status: "approved" }, { new: true });
    if (!payment) return res.status(404).json({ error: "Payment not found" });
    // Activate Pro for the user (1 month by default)
    const expiresAt = new Date(); expiresAt.setMonth(expiresAt.getMonth() + 1);
    await User.findOneAndUpdate({ email: payment.email }, { plan: "pro", proExpiresAt: expiresAt });
    res.json({ success: true, payment });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/reject/:id", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    await Payment.findByIdAndUpdate(req.params.id, { status: "rejected" });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

// ==========================================
// 8. ADMIN — USERS
// ==========================================
app.get("/admin/users", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const { page=1, limit=20, search="", filter="all" } = req.query;
    const query = {};
    if (search) query.email = { $regex: search, $options: "i" };
    if (filter === "pro")     { query.plan = "pro"; query.proExpiresAt = { $gt: new Date() }; }
    if (filter === "free")    query.$or = [{ plan: "free" }, { plan: "pro", proExpiresAt: { $lte: new Date() } }];
    if (filter === "blocked") query.isBlocked = true;

    const total = await User.countDocuments(query);
    const users = await User.find(query, { password: 0 })
      .sort({ createdAt: -1 })
      .skip((page-1)*limit)
      .limit(parseInt(limit));

    res.json({ users, total, page: parseInt(page), pages: Math.ceil(total/limit) });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/users/:id/block", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const { reason = "Admin action" } = req.body;
    await User.findByIdAndUpdate(req.params.id, { isBlocked: true, blockReason: reason });
    await SecurityLog.create({ type: "USER_BLOCKED", severity: "medium", ip: getIP(req), details: { userId: req.params.id, reason } });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/users/:id/unblock", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    await User.findByIdAndUpdate(req.params.id, { isBlocked: false, blockReason: "" });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/users/:id/grant-pro", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const months = parseInt(req.body.months) || 1;
    const expiresAt = new Date(); expiresAt.setMonth(expiresAt.getMonth() + months);
    await User.findByIdAndUpdate(req.params.id, { plan: "pro", proExpiresAt: expiresAt });
    res.json({ success: true, expiresAt });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/users/:id/revoke-pro", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    await User.findByIdAndUpdate(req.params.id, { plan: "free", proExpiresAt: null });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.delete("/admin/users/:id", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    await User.findByIdAndDelete(req.params.id);
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

// ==========================================
// 9. ADMIN — SECURITY LOGS
// ==========================================
app.get("/admin/security/logs", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const { page=1, limit=25, severity="", resolved="" } = req.query;
    const query = {};
    if (severity) query.severity = severity;
    if (resolved !== "") query.resolved = resolved === "true";

    const total = await SecurityLog.countDocuments(query);
    const unresolved = await SecurityLog.countDocuments({ resolved: false });
    const logs = await SecurityLog.find(query)
      .sort({ createdAt: -1 })
      .skip((page-1)*limit)
      .limit(parseInt(limit));

    res.json({ logs, total, unresolved, page: parseInt(page), pages: Math.ceil(total/limit) });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.patch("/admin/security/logs/:id/resolve", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    await SecurityLog.findByIdAndUpdate(req.params.id, { resolved: true });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.delete("/admin/security/logs/resolved", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    await SecurityLog.deleteMany({ resolved: true });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

// ==========================================
// 10. ADMIN — BLOCKED IPs
//     Your ADMIN_IP is always whitelisted — cannot be blocked
// ==========================================
app.get("/admin/security/blocked-ips", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const ips = await Ban.find().sort({ createdAt: -1 });
    res.json(ips);
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/security/block-ip", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  const { ip, reason = "Admin block", expiresInHours = null } = req.body;
  if (!ip) return res.status(400).json({ error: "IP required" });

  // Protect admin's own IP — can never be blocked
  if (ADMIN_IP_WHITELIST.includes(ip)) {
    return res.status(403).json({ error: "Cannot block a whitelisted admin IP." });
  }

  try {
    const expiresAt = expiresInHours ? new Date(Date.now() + expiresInHours * 3600000) : null;
    await Ban.findOneAndUpdate({ ip }, { ip, reason, blockedBy: "admin", expiresAt }, { upsert: true });
    await SecurityLog.create({ type: "IP_BLOCKED", severity: "high", ip: getIP(req), details: { targetIP: ip, reason } });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.delete("/admin/security/blocked-ips/:ip", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    await Ban.deleteOne({ ip: decodeURIComponent(req.params.ip) });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

// Legacy ban/unban endpoints (for backward compat)
app.post("/api/admin/ban", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: "IP required" });
  if (ADMIN_IP_WHITELIST.includes(ip)) return res.status(403).json({ error: "Cannot block a whitelisted admin IP." });
  try {
    await Ban.findOneAndUpdate({ ip }, { ip, reason, blockedBy: "admin", expiresAt: null }, { upsert: true });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/api/admin/unban", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  const { ip } = req.body;
  try { await Ban.deleteOne({ ip }); res.json({ success: true }); }
  catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/api/admin/banned-ips", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try { const list = await Ban.find({}); res.json({ success: true, banned: list }); }
  catch { res.status(500).json({ error: "Failed" }); }
});

// ==========================================
// 11. ADMIN — SYSTEM HEALTH
// ==========================================
app.get("/admin/system/health", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const mem = process.memoryUsage();
    const dbState = mongoose.connection.readyState === 1 ? "connected" : "disconnected";
    const blockedIPs = await Ban.countDocuments();
    const secAlerts = await SecurityLog.countDocuments({ resolved: false });
    const uptimeSec = process.uptime();
    const h = Math.floor(uptimeSec/3600), m = Math.floor((uptimeSec%3600)/60), s = Math.floor(uptimeSec%60);

    res.json({
      status: dbState === "connected" ? "healthy" : "degraded",
      db: dbState,
      uptimeHuman: `${h}h ${m}m ${s}s`,
      memory: { heapUsed: `${Math.round(mem.heapUsed/1024/1024)}MB`, rss: `${Math.round(mem.rss/1024/1024)}MB` },
      nodeVersion: process.version,
      env: process.env.NODE_ENV || "development",
      blockedIPs, secAlerts
    });
  } catch { res.status(500).json({ error: "Failed" }); }
});

// ==========================================
// 12. ADMIN — BROADCAST
// ==========================================
app.post("/admin/broadcast", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  const { subject, message, proOnly = false } = req.body;
  if (!subject || !message) return res.status(400).json({ error: "Subject and message required" });
  try {
    const query = { isBlocked: false };
    if (proOnly) { query.plan = "pro"; query.proExpiresAt = { $gt: new Date() }; }
    const users = await User.find(query, { email: 1 });
    // Placeholder: in real setup connect to email provider (SendGrid, etc.)
    // For now just return count
    res.json({ success: true, message: `Broadcast queued for ${users.length} users.`, count: users.length });
  } catch { res.status(500).json({ error: "Failed" }); }
});

// ==========================================
// 13. AUTH ROUTES
// ==========================================
app.post("/signup", async (req, res) => {
  const email    = sanitize(req.body.email);
  const password = sanitize(req.body.password);
  if (!email || !password) return res.status(400).json({ error: "All fields required" });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ error: "User already exists" });
    const hashed = await bcrypt.hash(password, 12);
    const user = await User.create({ email, password: hashed });
    const token = signToken({ userId: user._id, email: user.email, role: user.role });
    res.json({ success: true, token });
  } catch { res.status(500).json({ error: "Signup failed" }); }
});

app.post("/login", async (req, res) => {
  const email    = sanitize(req.body.email);
  const password = sanitize(req.body.password);
  const ip = getIP(req);
  if (!email || !password) return res.status(400).json({ error: "All fields required" });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ error: "Invalid email or password" });
    if (user.isBlocked) return res.status(403).json({ error: "Account blocked. Contact support." });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      await SecurityLog.create({ type: "FAILED_LOGIN", severity: "medium", ip, details: { email } });
      return res.status(401).json({ error: "Invalid email or password" });
    }
    user.lastLoginAt = new Date();
    user.lastLoginIP = ip;
    await user.save();
    const token = signToken({ userId: user._id, email: user.email, role: user.role });
    res.json({ success: true, token });
  } catch { res.status(500).json({ error: "Login failed" }); }
});

app.post("/settings/change-password", requireAuth, async (req, res) => {
  const oldPassword = sanitize(req.body.oldPassword);
  const newPassword = sanitize(req.body.newPassword);
  if (!oldPassword || !newPassword) return res.status(400).json({ error: "All fields required" });
  if (newPassword.length < 8) return res.status(400).json({ error: "Min 8 characters" });
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    const valid = await bcrypt.compare(oldPassword, user.password);
    if (!valid) return res.status(401).json({ error: "Current password incorrect" });
    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    res.json({ success: true, message: "Password updated" });
  } catch { res.status(500).json({ error: "Server error" }); }
});

// ==========================================
// 14. CHAT ROUTES
// ==========================================
app.post("/chat", requireAuth, async (req, res) => {
  const { messages, model, modelKey } = req.body;
  if (!Array.isArray(messages) || !messages.length) return res.status(400).json({ error: "Invalid messages" });
  try {
    // Track message count
    User.findByIdAndUpdate(req.user.userId, { $inc: { totalMessages: 1 } }).catch(()=>{});

    if (modelKey && GOOGLE_MODELS[modelKey]) return res.json({ response: await callGoogle(GOOGLE_MODELS[modelKey], messages) });
    if (modelKey?.startsWith("mistral"))      return res.json({ response: await callMistral(model, messages) });
    if (modelKey === "or")                     return res.json({ response: await callOR(model, messages) });
    res.json({ response: await callGroqRotating(model, messages) });
  } catch { res.status(500).json({ error: "Chat failed" }); }
});

app.post("/chat/stream", requireAuth, async (req, res) => {
  const { messages, model, modelKey } = req.body;
  if (!Array.isArray(messages) || !messages.length) return res.status(400).json({ error: "Invalid messages" });
  try {
    User.findByIdAndUpdate(req.user.userId, { $inc: { totalMessages: 1 } }).catch(()=>{});

    const success = await tryGroqStream(messages, model, res);
    if (!success) {
      res.setHeader("Content-Type", "text/event-stream");
      res.setHeader("Cache-Control", "no-cache");
      res.setHeader("Connection", "keep-alive");
      let text = "Streaming failed.";
      if (modelKey && GOOGLE_MODELS[modelKey]) text = await callGoogle(GOOGLE_MODELS[modelKey], messages);
      else if (modelKey?.startsWith("mistral"))  text = await callMistral(model, messages);
      res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: text } }] })}\n\n`);
      res.end();
    }
  } catch (err) { if (!res.writableEnded) res.status(500).send("Stream error"); }
});

// ==========================================
// 15. SERVER START
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  if (ADMIN_IP_WHITELIST.length) console.log(`🛡️  Admin IPs whitelisted: ${ADMIN_IP_WHITELIST.join(", ")}`);
  else console.log("⚠️  No ADMIN_IP set — add your IP to .env for protection");
});
