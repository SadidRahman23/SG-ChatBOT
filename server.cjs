require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const crypto = require("crypto");
const fetch = require("node-fetch");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const multer = require("multer");

const app = express();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ==========================================
// 1. CORS
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
// 2. RATE LIMITING
// ==========================================
const rateLimit = {};
setInterval(() => {
  const now = Date.now();
  for (const ip in rateLimit) {
    rateLimit[ip] = rateLimit[ip].filter(t => now - t < 60000);
    if (!rateLimit[ip].length) delete rateLimit[ip];
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
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("MongoDB error:", err));

const UserSchema = new mongoose.Schema({
  email:         { type: String, required: true, unique: true },
  password:      { type: String, required: true },
  displayName:   { type: String, default: "" },
  plan:          { type: String, default: "free" },
  proExpiresAt:  { type: Date, default: null },
  isBlocked:     { type: Boolean, default: false },
  blockReason:   { type: String, default: "" },
  lastLoginAt:   { type: Date, default: null },
  lastLoginIP:   { type: String, default: "" },
  totalMessages: { type: Number, default: 0 },
  msgCount:      { type: Number, default: 0 },
  msgWindowStart:{ type: Date, default: Date.now },
  role:          { type: String, default: "user" },
  settings:      { type: Object, default: {} },
  resetCode:     { type: String, default: null },
  resetExpires:  { type: Date, default: null },
  createdAt:     { type: Date, default: Date.now }
});
const User = mongoose.model("User", UserSchema);

const PaymentSchema = new mongoose.Schema({
  email:         { type: String, required: true },
  method:        { type: String, required: true },
  transactionId: { type: String, required: true },
  amount:        { type: Number, required: true },
  plan:          { type: String, required: true },
  status:        { type: String, default: "pending" },
  createdAt:     { type: Date, default: Date.now }
});
const Payment = mongoose.model("Payment", PaymentSchema);

const BanSchema = new mongoose.Schema({
  ip:        { type: String, required: true, unique: true },
  reason:    { type: String, default: "Violation of terms" },
  blockedBy: { type: String, default: "admin" },
  expiresAt: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
});
const Ban = mongoose.model("Ban", BanSchema);

const SecurityLogSchema = new mongoose.Schema({
  type:     { type: String, required: true },
  severity: { type: String, default: "medium" },
  ip:       { type: String, default: "" },
  details:  { type: mongoose.Schema.Types.Mixed, default: {} },
  resolved: { type: Boolean, default: false },
  createdAt:{ type: Date, default: Date.now }
});
const SecurityLog = mongoose.model("SecurityLog", SecurityLogSchema);

const ConversationSchema = new mongoose.Schema({
  userId:   { type: mongoose.Schema.Types.ObjectId, required: true },
  title:    { type: String, default: "New Chat" },
  messages: [{
    role:    { type: String },
    content: { type: mongoose.Schema.Types.Mixed }
  }],
  createdAt:{ type: Date, default: Date.now },
  updatedAt:{ type: Date, default: Date.now }
});
const Conversation = mongoose.model("Conversation", ConversationSchema);

// ==========================================
// 4. IP BAN MIDDLEWARE
// ==========================================
const ADMIN_IP_WHITELIST = (process.env.ADMIN_IP || "").split(",").map(s => s.trim()).filter(Boolean);

app.use(async (req, res, next) => {
  if (req.path.startsWith("/admin") || req.path.startsWith("/api/admin")) return next();
  const ip = req.headers["x-forwarded-for"]?.split(",")[0].trim() || req.socket.remoteAddress;
  if (ADMIN_IP_WHITELIST.includes(ip)) return next();
  try {
    await Ban.deleteMany({ expiresAt: { $lte: new Date(), $ne: null } });
    const banned = await Ban.findOne({ ip });
    if (banned) {
      await SecurityLog.create({ type: "BLOCKED_IP_HIT", severity: "high", ip, details: { reason: banned.reason } });
      return res.status(403).json({ error: "Access denied. Your IP is blocked." });
    }
  } catch (err) { console.error("Ban check error:", err); }
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

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
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

// Message limit: 25 per 4 hours for free users
const FREE_LIMIT = 25;
const WINDOW_MS  = 4 * 60 * 60 * 1000;

async function checkMsgLimit(userId) {
  const user = await User.findById(userId);
  if (!user) return { allowed: false, msgsLeft: 0 };
  if (user.plan === "pro" && user.proExpiresAt && new Date() < user.proExpiresAt) {
    return { allowed: true, msgsLeft: null, isPro: true };
  }
  const now = new Date();
  if (!user.msgWindowStart || (now - user.msgWindowStart) >= WINDOW_MS) {
    user.msgCount = 0; user.msgWindowStart = now; await user.save();
  }
  const msgsLeft = Math.max(0, FREE_LIMIT - user.msgCount);
  if (msgsLeft <= 0) {
    const minsLeft = Math.ceil((WINDOW_MS - (now - user.msgWindowStart)) / 60000);
    return { allowed: false, msgsLeft: 0, minsLeft };
  }
  return { allowed: true, msgsLeft: msgsLeft - 1 };
}

async function incrementMsgCount(userId) {
  await User.findByIdAndUpdate(userId, { $inc: { msgCount: 1, totalMessages: 1 } });
}

const ADMIN_SECRET = process.env.ADMIN_SECRET || "";
function verifyAdmin(req, res) {
  const secret = req.headers["x-admin-secret"] || req.body?.secret || "";
  if (!secret || !ADMIN_SECRET) { res.status(401).json({ error: "Unauthorized" }); return false; }
  try {
    if (secret.length !== ADMIN_SECRET.length) { res.status(401).json({ error: "Unauthorized" }); return false; }
    if (!crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(ADMIN_SECRET))) {
      SecurityLog.create({ type: "ADMIN_AUTH_FAIL", severity: "high", ip: getIP(req), details: { path: req.path } }).catch(() => {});
      res.status(401).json({ error: "Unauthorized" }); return false;
    }
  } catch { res.status(401).json({ error: "Unauthorized" }); return false; }
  return true;
}

// ==========================================
// 6. AI PROVIDERS
// ==========================================
const GROQ_KEYS    = (process.env.GROQ_API_KEYS || "").split(",").map(k => k.trim()).filter(Boolean);
const GOOGLE_MODELS = { "gemini-flash": "gemini-1.5-flash", "gemini-pro": "gemini-1.5-pro", "fast": "gemini-1.5-flash", "smart": "gemini-1.5-pro" };

// Model key → actual model string for Groq
const GROQ_MODELS = {
  fast:    "llama-3.1-8b-instant",
  smart:   "llama-3.3-70b-versatile",
  coding:  "llama-3.3-70b-versatile",
  deep:    "deepseek-r1-distill-llama-70b",
  default: "llama-3.1-8b-instant"
};

function resolveGroqModel(modelKey, modelRaw) {
  return GROQ_MODELS[modelKey] || modelRaw || GROQ_MODELS.default;
}

async function callGoogle(model, messages) {
  const resp = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${process.env.GEMINI_API_KEY}`,
    { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contents: messages.filter(m => m.role !== "system").map(m => ({ role: m.role === "assistant" ? "model" : "user", parts: [{ text: typeof m.content === "string" ? m.content : JSON.stringify(m.content) }] })) }) }
  );
  const data = await resp.json();
  return data?.candidates?.[0]?.content?.parts?.[0]?.text || "Error calling Google AI";
}

async function callMistral(model, messages) {
  const resp = await fetch("https://api.mistral.ai/v1/chat/completions", {
    method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Bearer ${process.env.MISTRAL_API_KEY}` },
    body: JSON.stringify({ model, messages })
  });
  const data = await resp.json();
  return data?.choices?.[0]?.message?.content || "Error calling Mistral";
}

async function callOR(model, messages) {
  const resp = await fetch("https://openrouter.ai/api/v1/chat/completions", {
    method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Bearer ${process.env.OR_API_KEY}` },
    body: JSON.stringify({ model, messages })
  });
  const data = await resp.json();
  return data?.choices?.[0]?.message?.content || "Error calling OpenRouter";
}

async function callGroqRotating(model, messages) {
  for (const key of GROQ_KEYS) {
    try {
      const resp = await fetch("https://api.groq.com/openai/v1/chat/completions", {
        method: "POST", headers: { "Content-Type": "application/json", "Authorization": `Bearer ${key}` },
        body: JSON.stringify({ model, messages, max_tokens: 4096 })
      });
      if (resp.status === 429 || !resp.ok) continue;
      const data = await resp.json();
      return data?.choices?.[0]?.message?.content || "Error";
    } catch { continue; }
  }
  return "All Groq keys rate limited or failed.";
}

// ==========================================
// 7. AUTH ROUTES
// ==========================================
app.post("/signup", async (req, res) => {
  const email    = sanitize(req.body.email);
  const password = sanitize(req.body.password);
  if (!email || !password) return res.status(400).json({ error: "All fields required" });
  if (password.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "User already exists" });
    const hashed = await bcrypt.hash(password, 12);
    const user   = await User.create({ email, password: hashed });
    const token  = signToken({ userId: user._id, email: user.email, role: user.role });
    res.json({ success: true, token, email: user.email });
  } catch { res.status(500).json({ message: "Signup failed" }); }
});

app.post("/login", async (req, res) => {
  const email    = sanitize(req.body.email);
  const password = sanitize(req.body.password);
  const ip       = getIP(req);
  if (!email || !password) return res.status(400).json({ message: "All fields required" });
  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid email or password" });
    if (user.isBlocked) return res.status(403).json({ message: "Account blocked. Contact support." });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      await SecurityLog.create({ type: "FAILED_LOGIN", severity: "medium", ip, details: { email } }).catch(() => {});
      return res.status(401).json({ message: "Invalid email or password" });
    }
    user.lastLoginAt = new Date(); user.lastLoginIP = ip; await user.save();
    const token = signToken({ userId: user._id, email: user.email, role: user.role });
    res.json({ success: true, token, email: user.email });
  } catch { res.status(500).json({ message: "Login failed" }); }
});

// ── Password Reset ──
app.post("/forgot-password", async (req, res) => {
  const email = sanitize(req.body.email);
  try {
    const user = await User.findOne({ email });
    if (!user) return res.json({ success: true, message: "If that email exists, a code was sent." });
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    user.resetCode = code; user.resetExpires = new Date(Date.now() + 15 * 60000);
    await user.save();
    // TODO: send email with code via SendGrid/etc.
    console.log(`Reset code for ${email}: ${code}`); // dev only
    res.json({ success: true, message: "Reset code sent." });
  } catch { res.status(500).json({ message: "Error" }); }
});

app.post("/reset-password", async (req, res) => {
  const { email, code, newPassword } = req.body;
  try {
    const user = await User.findOne({ email, resetCode: code });
    if (!user || user.resetExpires < new Date()) return res.status(400).json({ message: "Invalid or expired code." });
    if (!newPassword || newPassword.length < 8) return res.status(400).json({ message: "Password too short." });
    user.password = await bcrypt.hash(newPassword, 12);
    user.resetCode = null; user.resetExpires = null; await user.save();
    res.json({ success: true });
  } catch { res.status(500).json({ message: "Error" }); }
});

// ── Settings ──
app.get("/status", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ error: "User not found" });
    const isPro = user.plan === "pro" && user.proExpiresAt && new Date() < user.proExpiresAt;
    const now = new Date();
    let msgsLeft = null;
    if (!isPro) {
      if (!user.msgWindowStart || (now - user.msgWindowStart) >= WINDOW_MS) { msgsLeft = FREE_LIMIT; }
      else { msgsLeft = Math.max(0, FREE_LIMIT - user.msgCount); }
    }
    res.json({
      plan: isPro ? "pro" : "free",
      proExpires: user.proExpiresAt,
      msgsLeft,
      email: user.email,
      displayName: user.displayName
    });
  } catch { res.status(500).json({ error: "Error" }); }
});

app.get("/settings", requireAuth, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId, { password: 0 });
    if (!user) return res.status(404).json({ error: "Not found" });
    res.json({ displayName: user.displayName, settings: user.settings || {} });
  } catch { res.status(500).json({ error: "Error" }); }
});

app.post("/settings", requireAuth, async (req, res) => {
  try {
    const { displayName, settings } = req.body;
    await User.findByIdAndUpdate(req.user.userId, { displayName, settings });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Error" }); }
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
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Error" }); }
});

// ── Payment (submit from frontend) ──
app.post("/payment/submit", requireAuth, async (req, res) => {
  const { method, transactionId, amount, plan } = req.body;
  if (!method || !transactionId || !amount || !plan) return res.status(400).json({ error: "All fields required" });
  try {
    const payment = await Payment.create({ email: req.user.email, method, transactionId, amount, plan });
    res.json({ success: true, payment });
  } catch { res.status(500).json({ error: "Failed to submit payment" }); }
});

// ── TTS Key (optional ElevenLabs) ──
app.get("/tts-key", requireAuth, (req, res) => {
  const key = process.env.ELEVENLABS_API_KEY || "";
  if (!key) return res.status(404).json({ error: "No TTS key configured" });
  res.json({ key });
});

// ==========================================
// 8. CONVERSATION ROUTES
// ==========================================
app.get("/conversations", requireAuth, async (req, res) => {
  try {
    const convs = await Conversation.find({ userId: req.user.userId }, { messages: 0 }).sort({ updatedAt: -1 }).limit(50);
    res.json(convs);
  } catch { res.status(500).json({ error: "Error" }); }
});

app.get("/conversations/:id", requireAuth, async (req, res) => {
  try {
    const conv = await Conversation.findOne({ _id: req.params.id, userId: req.user.userId });
    if (!conv) return res.status(404).json({ error: "Not found" });
    res.json(conv);
  } catch { res.status(500).json({ error: "Error" }); }
});

app.delete("/conversations/:id", requireAuth, async (req, res) => {
  try {
    await Conversation.deleteOne({ _id: req.params.id, userId: req.user.userId });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Error" }); }
});

// ==========================================
// 9. CHAT ROUTES (FormData + JSON support)
// ==========================================

// Parse messages from either FormData or JSON body
function getMessages(req) {
  try {
    const raw = req.body?.messages;
    if (typeof raw === "string") return JSON.parse(raw);
    if (Array.isArray(raw)) return raw;
  } catch {}
  return null;
}

app.post("/chat", requireAuth, upload.single("file"), async (req, res) => {
  const messages  = getMessages(req);
  const modelKey  = req.body?.modelKey || "fast";
  const personaKey= req.body?.personaKey || "default";
  let convId      = req.body?.conversationId || null;

  if (!Array.isArray(messages) || !messages.length) {
    return res.status(400).json({ error: "Invalid messages" });
  }

  // Check message limit
  const limit = await checkMsgLimit(req.user.userId);
  if (!limit.allowed) {
    return res.status(429).json({ reply: "limit_reached", minsLeft: limit.minsLeft });
  }

  try {
    // Handle uploaded image
    if (req.file && req.file.mimetype.startsWith("image/")) {
      const base64 = req.file.buffer.toString("base64");
      const lastMsg = messages[messages.length - 1];
      if (lastMsg?.role === "user" && typeof lastMsg.content === "string") {
        messages[messages.length - 1] = {
          role: "user",
          content: [
            { type: "image_url", image_url: { url: `data:${req.file.mimetype};base64,${base64}` } },
            { type: "text", text: lastMsg.content || "Analyze this image." }
          ]
        };
      }
    }

    let reply;
    const groqModel = resolveGroqModel(modelKey);

    // Try Groq first, fallback to Google
    try {
      reply = await callGroqRotating(groqModel, messages);
      if (!reply || reply.includes("rate limited")) throw new Error("Groq failed");
    } catch {
      if (GOOGLE_MODELS[modelKey] || process.env.GEMINI_API_KEY) {
        reply = await callGoogle(GOOGLE_MODELS[modelKey] || "gemini-1.5-flash", messages);
      } else {
        reply = "Sorry, all AI providers are currently unavailable. Please try again.";
      }
    }

    await incrementMsgCount(req.user.userId);

    // Save conversation
    const userMsg = messages[messages.length - 1];
    if (convId) {
      await Conversation.findByIdAndUpdate(convId, {
        $push: { messages: { $each: [userMsg, { role: "assistant", content: reply }] } },
        updatedAt: new Date()
      });
    } else {
      const title = typeof userMsg.content === "string"
        ? userMsg.content.slice(0, 50)
        : "New Chat";
      const conv = await Conversation.create({
        userId: req.user.userId,
        title,
        messages: [...messages, { role: "assistant", content: reply }]
      });
      convId = conv._id;
    }

    res.json({ reply, conversationId: convId, msgsLeft: limit.msgsLeft });
  } catch (err) {
    console.error("Chat error:", err);
    res.status(500).json({ error: "Chat failed" });
  }
});

// ── Streaming chat ──
app.post("/chat/stream", requireAuth, upload.single("file"), async (req, res) => {
  const messages  = getMessages(req);
  const modelKey  = req.body?.modelKey || "fast";
  let convId      = req.body?.conversationId || null;

  if (!Array.isArray(messages) || !messages.length) {
    return res.status(400).json({ error: "Invalid messages" });
  }

  const limit = await checkMsgLimit(req.user.userId);
  if (!limit.allowed) {
    return res.status(429).json({ reply: "limit_reached", minsLeft: limit.minsLeft });
  }

  // Set SSE headers immediately
  res.setHeader("Content-Type", "text/event-stream");
  res.setHeader("Cache-Control", "no-cache");
  res.setHeader("Connection", "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");

  const sendChunk = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

  try {
    const groqModel = resolveGroqModel(modelKey);
    let fullText = "";
    let streamSuccess = false;

    // Try Groq streaming
    for (const key of GROQ_KEYS) {
      try {
        const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
          method: "POST",
          headers: { "Content-Type": "application/json", "Authorization": `Bearer ${key}` },
          body: JSON.stringify({ model: groqModel, messages, stream: true, max_tokens: 4096 })
        });
        if (r.status === 429 || !r.ok) continue;

        const reader = r.body;
        let buf = "";

        for await (const chunk of reader) {
          buf += chunk.toString();
          const lines = buf.split("\n");
          buf = lines.pop() || "";
          for (const line of lines) {
            if (!line.startsWith("data:")) continue;
            const raw = line.slice(5).trim();
            if (raw === "[DONE]") { streamSuccess = true; break; }
            try {
              const parsed = JSON.parse(raw);
              const delta = parsed.choices?.[0]?.delta?.content || "";
              if (delta) { fullText += delta; sendChunk({ t: delta }); }
            } catch {}
          }
          if (streamSuccess) break;
        }

        if (fullText) { streamSuccess = true; break; }
      } catch { continue; }
    }

    // Fallback to non-streaming if Groq failed
    if (!streamSuccess || !fullText) {
      try {
        fullText = await callGoogle(GOOGLE_MODELS[modelKey] || "gemini-1.5-flash", messages);
        // Send as chunks for consistent UX
        const words = fullText.split(" ");
        for (let i = 0; i < words.length; i += 3) {
          sendChunk({ t: words.slice(i, i + 3).join(" ") + " " });
          await new Promise(r => setTimeout(r, 20));
        }
      } catch {
        sendChunk({ error: "All AI providers failed. Please try again." });
        res.end(); return;
      }
    }

    await incrementMsgCount(req.user.userId);

    // Save conversation
    const userMsg = messages[messages.length - 1];
    if (convId) {
      await Conversation.findByIdAndUpdate(convId, {
        $push: { messages: { $each: [userMsg, { role: "assistant", content: fullText }] } },
        updatedAt: new Date()
      });
    } else {
      const title = typeof userMsg.content === "string" ? userMsg.content.slice(0, 50) : "New Chat";
      const conv = await Conversation.create({
        userId: req.user.userId, title,
        messages: [...messages, { role: "assistant", content: fullText }]
      });
      convId = conv._id;
    }

    sendChunk({ done: true, conversationId: convId, msgsLeft: limit.msgsLeft });
    res.end();
  } catch (err) {
    if (!res.writableEnded) {
      sendChunk({ error: "Stream error. Please try again." });
      res.end();
    }
  }
});

// ==========================================
// 10. ADMIN — STATS
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

    res.json({ total, pro, blocked, pendingPayments,
      revenue: totalPaymentsData[0]?.total || 0, totalPayments: totalPaymentsData[0]?.count || 0,
      unresolved: unresolvedLogs, critical, newToday, signupsByDay, monthlyRevenue
    });
  } catch(err) { console.error(err); res.status(500).json({ error: "Stats fetch failed" }); }
});

// ==========================================
// 11. ADMIN — PAYMENTS
// ==========================================
app.get("/admin/payments", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try { res.json(await Payment.find().sort({ createdAt: -1 }).limit(200)); }
  catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/approve/:id", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const payment = await Payment.findByIdAndUpdate(req.params.id, { status: "approved" }, { new: true });
    if (!payment) return res.status(404).json({ error: "Not found" });
    const exp = new Date(); exp.setMonth(exp.getMonth() + 1);
    await User.findOneAndUpdate({ email: payment.email }, { plan: "pro", proExpiresAt: exp });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/reject/:id", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try { await Payment.findByIdAndUpdate(req.params.id, { status: "rejected" }); res.json({ success: true }); }
  catch { res.status(500).json({ error: "Failed" }); }
});

// ==========================================
// 12. ADMIN — USERS
// ==========================================
app.get("/admin/users", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const { page=1, limit=20, search="", filter="all" } = req.query;
    const query = {};
    if (search) query.email = { $regex: search, $options: "i" };
    if (filter === "pro")     { query.plan = "pro"; query.proExpiresAt = { $gt: new Date() }; }
    if (filter === "free")    query.$or = [{ plan: "free" }, { proExpiresAt: { $lte: new Date() } }];
    if (filter === "blocked") query.isBlocked = true;
    const total = await User.countDocuments(query);
    const users = await User.find(query, { password: 0 }).sort({ createdAt: -1 }).skip((page-1)*limit).limit(parseInt(limit));
    res.json({ users, total, page: parseInt(page), pages: Math.ceil(total/limit) });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/users/:id/block", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const { reason = "Admin action" } = req.body;
    await User.findByIdAndUpdate(req.params.id, { isBlocked: true, blockReason: reason });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/users/:id/unblock", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try { await User.findByIdAndUpdate(req.params.id, { isBlocked: false, blockReason: "" }); res.json({ success: true }); }
  catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/users/:id/grant-pro", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const months = parseInt(req.body.months) || 1;
    const exp = new Date(); exp.setMonth(exp.getMonth() + months);
    await User.findByIdAndUpdate(req.params.id, { plan: "pro", proExpiresAt: exp });
    res.json({ success: true, expiresAt: exp });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/users/:id/revoke-pro", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try { await User.findByIdAndUpdate(req.params.id, { plan: "free", proExpiresAt: null }); res.json({ success: true }); }
  catch { res.status(500).json({ error: "Failed" }); }
});

app.delete("/admin/users/:id", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try { await User.findByIdAndDelete(req.params.id); res.json({ success: true }); }
  catch { res.status(500).json({ error: "Failed" }); }
});

// ==========================================
// 13. ADMIN — SECURITY
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
    const logs = await SecurityLog.find(query).sort({ createdAt: -1 }).skip((page-1)*limit).limit(parseInt(limit));
    res.json({ logs, total, unresolved, page: parseInt(page), pages: Math.ceil(total/limit) });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.patch("/admin/security/logs/:id/resolve", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try { await SecurityLog.findByIdAndUpdate(req.params.id, { resolved: true }); res.json({ success: true }); }
  catch { res.status(500).json({ error: "Failed" }); }
});

app.delete("/admin/security/logs/resolved", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try { await SecurityLog.deleteMany({ resolved: true }); res.json({ success: true }); }
  catch { res.status(500).json({ error: "Failed" }); }
});

app.get("/admin/security/blocked-ips", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try { res.json(await Ban.find().sort({ createdAt: -1 })); }
  catch { res.status(500).json({ error: "Failed" }); }
});

app.post("/admin/security/block-ip", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  const { ip, reason = "Admin block", expiresInHours = null } = req.body;
  if (!ip) return res.status(400).json({ error: "IP required" });
  if (ADMIN_IP_WHITELIST.includes(ip)) return res.status(403).json({ error: "Cannot block a whitelisted admin IP." });
  try {
    const expiresAt = expiresInHours ? new Date(Date.now() + expiresInHours * 3600000) : null;
    await Ban.findOneAndUpdate({ ip }, { ip, reason, blockedBy: "admin", expiresAt }, { upsert: true });
    res.json({ success: true });
  } catch { res.status(500).json({ error: "Failed" }); }
});

app.delete("/admin/security/blocked-ips/:ip", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try { await Ban.deleteOne({ ip: decodeURIComponent(req.params.ip) }); res.json({ success: true }); }
  catch { res.status(500).json({ error: "Failed" }); }
});

// Legacy endpoints
app.post("/api/admin/ban", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  const { ip, reason } = req.body;
  if (!ip) return res.status(400).json({ error: "IP required" });
  if (ADMIN_IP_WHITELIST.includes(ip)) return res.status(403).json({ error: "Cannot block a whitelisted admin IP." });
  try { await Ban.findOneAndUpdate({ ip }, { ip, reason, blockedBy: "admin", expiresAt: null }, { upsert: true }); res.json({ success: true }); }
  catch { res.status(500).json({ error: "Failed" }); }
});
app.post("/api/admin/unban", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try { await Ban.deleteOne({ ip: req.body.ip }); res.json({ success: true }); }
  catch { res.status(500).json({ error: "Failed" }); }
});
app.post("/api/admin/banned-ips", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try { res.json({ success: true, banned: await Ban.find({}) }); }
  catch { res.status(500).json({ error: "Failed" }); }
});

// ==========================================
// 14. ADMIN — SYSTEM HEALTH
// ==========================================
app.get("/admin/system/health", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  try {
    const mem = process.memoryUsage();
    const dbState = mongoose.connection.readyState === 1 ? "connected" : "disconnected";
    const blockedIPs = await Ban.countDocuments();
    const secAlerts  = await SecurityLog.countDocuments({ resolved: false });
    const uptimeSec  = process.uptime();
    const h = Math.floor(uptimeSec/3600), m = Math.floor((uptimeSec%3600)/60), s = Math.floor(uptimeSec%60);
    res.json({
      status: dbState === "connected" ? "healthy" : "degraded", db: dbState,
      uptimeHuman: `${h}h ${m}m ${s}s`,
      memory: { heapUsed: `${Math.round(mem.heapUsed/1024/1024)}MB` },
      nodeVersion: process.version, env: process.env.NODE_ENV || "development",
      blockedIPs, secAlerts
    });
  } catch { res.status(500).json({ error: "Failed" }); }
});

// ==========================================
// 15. ADMIN — BROADCAST
// ==========================================
app.post("/admin/broadcast", async (req, res) => {
  if (!verifyAdmin(req, res)) return;
  const { subject, message, proOnly = false } = req.body;
  if (!subject || !message) return res.status(400).json({ error: "Subject and message required" });
  try {
    const query = { isBlocked: false };
    if (proOnly) { query.plan = "pro"; query.proExpiresAt = { $gt: new Date() }; }
    const users = await User.find(query, { email: 1 });
    res.json({ success: true, message: `Broadcast queued for ${users.length} users.`, count: users.length });
  } catch { res.status(500).json({ error: "Failed" }); }
});

// ==========================================
// 16. START
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server on port ${PORT}`);
  if (ADMIN_IP_WHITELIST.length) console.log(`🛡️  Admin IPs: ${ADMIN_IP_WHITELIST.join(", ")}`);
  else console.log("⚠️  No ADMIN_IP set in .env");
});
