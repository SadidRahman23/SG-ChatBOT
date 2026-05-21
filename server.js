import express        from "express";
import mongoose       from "mongoose";
import fetch          from "node-fetch";
import bcrypt         from "bcryptjs";
import jwt            from "jsonwebtoken";
import cors           from "cors";
import dotenv         from "dotenv";
import path           from "path";
import rateLimit      from "express-rate-limit";
import multer         from "multer";
import { fileURLToPath } from "url";
import crypto         from "crypto";
import nodemailer     from "nodemailer";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, ".env") });

// ═══════════════════════════════════════════
// ENV CHECK
// ═══════════════════════════════════════════
const REQUIRED_ENV = ["MONGO_URI", "OPENROUTER_KEY", "JWT_SECRET", "ADMIN_SECRET", "EMAIL_USER", "EMAIL_PASS"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) throw new Error(`Missing env: ${key}`);
}

const JWT_SECRET   = process.env.JWT_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET;
const PORT         = process.env.PORT || 3000;
const MAX_HISTORY  = 20;
const FREE_LIMIT   = 25;
const FREE_WINDOW  = 4 * 60 * 60 * 1000;

// ═══════════════════════════════════════════
// NODEMAILER — Gmail SMTP
// ═══════════════════════════════════════════
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function sendEmail(to, subject, html) {
  try {
    await transporter.sendMail({
      from: `"SG ChatBOT" <${process.env.EMAIL_USER}>`,
      to,
      subject,
      html,
    });
    return true;
  } catch (err) {
    console.error("Email error:", err.message);
    return false;
  }
}

// ═══════════════════════════════════════════
// APP SETUP
// ═══════════════════════════════════════════
const app = express();
app.set("trust proxy", 1);

// Force HTTPS in production
app.use((req, res, next) => {
  if (
    process.env.NODE_ENV === "production" &&
    req.headers["x-forwarded-proto"] !== "https"
  ) {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// Security headers
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

// CORS — whitelist only
app.use(cors({
  origin: [
    "https://sg-chatbot-a2h.pages.dev",
    "https://sgchatbotofficial.netlify.app",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5500",
  ],
  methods: ["GET", "POST", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "x-admin-secret"],
  credentials: false,
}));

// Limit JSON body size
app.use(express.json({ limit: "16kb" }));

// ═══════════════════════════════════════════
// MULTER — File upload with type validation
// ═══════════════════════════════════════════
const ALLOWED_MIME = new Set([
  "image/jpeg", "image/png", "image/gif", "image/webp",
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "text/plain", "text/csv",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
]);

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB max
  fileFilter: (req, file, cb) => {
    if (ALLOWED_MIME.has(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`File type not allowed: ${file.mimetype}`));
    }
  },
});

// ═══════════════════════════════════════════
// RATE LIMITERS
// ═══════════════════════════════════════════
const authLimiter  = rateLimit({ windowMs: 15 * 60 * 1000, max: 15, message: { message: "Too many attempts. Try later." } });
const chatLimiter  = rateLimit({ windowMs: 60 * 1000,       max: 30 });
const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, message: { message: "Too many admin requests." } });
const resetLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 5,  message: { message: "Too many reset attempts." } });

// ═══════════════════════════════════════════
// DATABASE
// ═══════════════════════════════════════════
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => { console.error("❌ MongoDB failed:", err.message); process.exit(1); });

// ═══════════════════════════════════════════
// MODELS
// ═══════════════════════════════════════════
const userSchema = new mongoose.Schema({
  email:          { type: String, required: true, unique: true, lowercase: true, trim: true, maxlength: 254 },
  password:       { type: String, required: true },
  plan:           { type: String, enum: ["free", "pro"], default: "free" },
  proExpiresAt:   { type: Date, default: null },
  msgCount:       { type: Number, default: 0 },
  msgWindowStart: { type: Date, default: null },
  resetToken:     { type: String, default: null },
  resetTokenExp:  { type: Date, default: null },
  loginAttempts:  { type: Number, default: 0 },
  lockUntil:      { type: Date, default: null },
  displayName:    { type: String, default: "", maxlength: 50 },
  settings: {
    theme:           { type: String, enum: ["dark","light","system"], default: "dark" },
    language:        { type: String, default: "en" },
    parentalControl: { type: Boolean, default: false },
    typewriter:      { type: Boolean, default: true },
    fontSize:        { type: String, enum: ["sm","md","lg"], default: "md" },
    soundEnabled:    { type: Boolean, default: false },
    autoSaveChats:   { type: Boolean, default: true },
  },
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

const paymentSchema = new mongoose.Schema({
  userId:        { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  email:         { type: String, required: true },
  method:        { type: String, enum: ["bkash", "nagad"], required: true },
  transactionId: { type: String, required: true, trim: true },
  amount:        { type: Number, required: true },
  plan:          { type: String, enum: ["monthly", "yearly"], required: true },
  status:        { type: String, enum: ["pending", "approved", "rejected"], default: "pending" },
}, { timestamps: true });
const Payment = mongoose.model("Payment", paymentSchema);

const conversationSchema = new mongoose.Schema({
  userId:   { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title:    { type: String, default: "New Chat" },
  messages: [{
    role:      { type: String, enum: ["user","assistant","system"] },
    content:   { type: mongoose.Schema.Types.Mixed },
    createdAt: { type: Date, default: Date.now },
  }],
  updatedAt: { type: Date, default: Date.now },
}, { timestamps: true });
const Conversation = mongoose.model("Conversation", conversationSchema);

// ═══════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════
function sanitize(input) {
  if (typeof input === "string") {
    return input.replace(/[\$\x00]/g, "").trim().slice(0, 1000);
  }
  if (typeof input === "object" && input !== null) {
    const clean = {};
    for (const key of Object.keys(input)) {
      const safeKey = key.replace(/[\$\.]/g, "_").slice(0, 100);
      clean[safeKey] = sanitize(input[key]);
    }
    return clean;
  }
  return input;
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

function isProActive(user) {
  return user.plan === "pro" && user.proExpiresAt && new Date() < new Date(user.proExpiresAt);
}

function checkWindow(user) {
  const now = Date.now();
  if (!user.msgWindowStart || (now - new Date(user.msgWindowStart).getTime()) >= FREE_WINDOW) {
    user.msgCount = 0;
    user.msgWindowStart = new Date();
  }
}

function minsUntilReset(user) {
  if (!user.msgWindowStart) return 0;
  const elapsed = Date.now() - new Date(user.msgWindowStart).getTime();
  return Math.ceil(Math.max(0, FREE_WINDOW - elapsed) / 60000);
}

function isLocked(user) {
  return user.lockUntil && new Date() < new Date(user.lockUntil);
}

// ═══════════════════════════════════════════
// AUTH MIDDLEWARE
// ═══════════════════════════════════════════
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer "))
    return res.status(401).json({ reply: "Authorization token missing." });
  try {
    req.user = jwt.verify(header.slice(7), JWT_SECRET);
    next();
  } catch {
    return res.status(401).json({ reply: "Invalid or expired token." });
  }
}

function adminAuth(req, res, next) {
  const secret = req.headers["x-admin-secret"] || "";
  const valid  = Buffer.from(secret).length === Buffer.from(ADMIN_SECRET).length &&
                 crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(ADMIN_SECRET));
  if (!valid) return res.status(403).json({ message: "Forbidden" });
  next();
}

// ═══════════════════════════════════════════
// SIGNUP
// ═══════════════════════════════════════════
app.post("/signup", authLimiter, async (req, res) => {
  try {
    const body     = sanitize(req.body);
    const email    = body.email;
    const password = body.password;

    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });
    if (!isValidEmail(email))
      return res.status(400).json({ message: "Invalid email format" });
    if (password.length < 8 || password.length > 128)
      return res.status(400).json({ message: "Password must be 8–128 characters" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: "User already exists" });

    const hash = await bcrypt.hash(password, 12);
    await User.create({ email, password: hash });
    res.json({ message: "Account created" });
  } catch {
    res.status(500).json({ message: "Signup error" });
  }
});

// ═══════════════════════════════════════════
// LOGIN
// ═══════════════════════════════════════════
app.post("/login", authLimiter, async (req, res) => {
  try {
    const body     = sanitize(req.body);
    const email    = body.email;
    const password = body.password;

    if (!email || !password)
      return res.status(401).json({ message: "Invalid login" });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(401).json({ message: "Invalid email or password" });

    if (isLocked(user))
      return res.status(423).json({ message: "Account temporarily locked. Try again later." });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) {
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 15 * 60 * 1000);
        user.loginAttempts = 0;
      }
      await user.save();
      return res.status(401).json({ message: "Invalid email or password" });
    }

    user.loginAttempts = 0;
    user.lockUntil     = null;
    await user.save();

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch {
    res.status(500).json({ message: "Login error" });
  }
});

// ═══════════════════════════════════════════
// STATUS
// ═══════════════════════════════════════════
app.get("/status", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password -resetToken");
    if (!user) return res.status(404).json({ message: "User not found" });

    const pro = isProActive(user);
    checkWindow(user);

    res.json({
      email:      user.email,
      plan:       pro ? "pro" : "free",
      msgsLeft:   pro ? null : Math.max(0, FREE_LIMIT - user.msgCount),
      freeLimit:  FREE_LIMIT,
      minsLeft:   pro ? null : minsUntilReset(user),
      proExpires: user.proExpiresAt,
    });
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

// ═══════════════════════════════════════════
// FORGOT PASSWORD
// ═══════════════════════════════════════════
app.post("/forgot-password", resetLimiter, async (req, res) => {
  try {
    const email = sanitize(req.body).email;
    if (!email || !isValidEmail(email))
      return res.json({ message: "If this email exists, a reset code has been sent." });

    const user = await User.findOne({ email });
    if (!user)
      return res.json({ message: "If this email exists, a reset code has been sent." });

    const code    = crypto.randomInt(100000, 999999).toString();
    const expires = new Date(Date.now() + 15 * 60 * 1000);

    user.resetToken    = await bcrypt.hash(code, 8);
    user.resetTokenExp = expires;
    await user.save();

    const emailSent = await sendEmail(
      email,
      "🔑 SG ChatBOT — Password Reset Code",
      `
      <div style="font-family:sans-serif;max-width:480px;margin:0 auto;background:#0b0f17;color:#e4ecf7;padding:32px;border-radius:16px;border:1px solid rgba(255,255,255,0.1)">
        <h2 style="color:#4f8eff;margin-bottom:8px">SG ChatBOT</h2>
        <p style="color:#8a9bb5;margin-bottom:24px">Password Reset Request</p>
        <p>Your reset code is:</p>
        <div style="font-size:36px;font-weight:800;letter-spacing:8px;color:#4f8eff;background:rgba(79,142,255,0.1);padding:20px;border-radius:12px;text-align:center;margin:16px 0">${code}</div>
        <p style="color:#8a9bb5;font-size:13px">This code expires in <strong style="color:#e4ecf7">15 minutes</strong>.</p>
        <p style="color:#8a9bb5;font-size:13px">If you didn't request this, ignore this email.</p>
        <hr style="border:none;border-top:1px solid rgba(255,255,255,0.08);margin:24px 0">
        <p style="color:#4a5a72;font-size:12px">SG ChatBOT · Built by Mohammed Sadid Rahman</p>
      </div>
      `
    );

    if (!emailSent) {
      console.log(`🔑 Reset code for ${email}: ${code}`);
    }

    res.json({ message: "If this email exists, a reset code has been sent." });
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

// ═══════════════════════════════════════════
// RESET PASSWORD
// ═══════════════════════════════════════════
app.post("/reset-password", resetLimiter, async (req, res) => {
  try {
    const body        = sanitize(req.body);
    const email       = body.email;
    const code        = body.code;
    const newPassword = body.newPassword;

    if (!email || !code || !newPassword)
      return res.status(400).json({ message: "All fields required" });
    if (newPassword.length < 8 || newPassword.length > 128)
      return res.status(400).json({ message: "Password must be 8–128 characters" });

    const user = await User.findOne({ email });
    if (!user || !user.resetToken || !user.resetTokenExp)
      return res.status(400).json({ message: "Invalid or expired code" });
    if (new Date() > user.resetTokenExp)
      return res.status(400).json({ message: "Reset code expired" });

    const valid = await bcrypt.compare(code, user.resetToken);
    if (!valid) return res.status(400).json({ message: "Invalid reset code" });

    user.password      = await bcrypt.hash(newPassword, 12);
    user.resetToken    = null;
    user.resetTokenExp = null;
    user.loginAttempts = 0;
    user.lockUntil     = null;
    await user.save();

    res.json({ message: "Password reset successfully" });
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

// ═══════════════════════════════════════════
// PAYMENT SUBMIT
// ═══════════════════════════════════════════
app.post("/payment/submit", auth, async (req, res) => {
  try {
    const body = sanitize(req.body);
    const { method, transactionId, plan } = body;

    if (!method || !transactionId || !plan)
      return res.status(400).json({ message: "Missing fields" });
    if (!["bkash", "nagad"].includes(method))
      return res.status(400).json({ message: "Invalid method" });
    if (!["monthly", "yearly"].includes(plan))
      return res.status(400).json({ message: "Invalid plan" });
    if (transactionId.length < 6 || transactionId.length > 50)
      return res.status(400).json({ message: "Invalid transaction ID" });

    const duplicate = await Payment.findOne({ transactionId });
    if (duplicate) return res.status(409).json({ message: "Transaction ID already used" });

    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    const amount = plan === "monthly" ? 99 : 799;

    await Payment.create({
      userId: user._id,
      email:  user.email,
      method,
      transactionId,
      amount,
      plan,
    });

    res.json({ message: "Payment submitted! We will verify within 24 hours." });
  } catch {
    res.status(500).json({ message: "Payment error" });
  }
});

// ═══════════════════════════════════════════
// ADMIN ROUTES
// ═══════════════════════════════════════════
app.get("/admin/payments", adminLimiter, adminAuth, async (req, res) => {
  try {
    const payments = await Payment.find().sort({ createdAt: -1 });
    res.json(payments);
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

app.post("/admin/approve/:paymentId", adminLimiter, adminAuth, async (req, res) => {
  try {
    const payment = await Payment.findById(req.params.paymentId);
    if (!payment) return res.status(404).json({ message: "Not found" });

    payment.status = "approved";
    await payment.save();

    const user = await User.findById(payment.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const expires = new Date();
    payment.plan === "monthly"
      ? expires.setMonth(expires.getMonth() + 1)
      : expires.setFullYear(expires.getFullYear() + 1);

    user.plan         = "pro";
    user.proExpiresAt = expires;
    await user.save();

    res.json({ message: `Pro activated for ${user.email} until ${expires.toDateString()}` });
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

app.post("/admin/reject/:paymentId", adminLimiter, adminAuth, async (req, res) => {
  try {
    const payment = await Payment.findById(req.params.paymentId);
    if (!payment) return res.status(404).json({ message: "Not found" });
    payment.status = "rejected";
    await payment.save();
    res.json({ message: "Payment rejected" });
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

// ═══════════════════════════════════════════
// CHAT — Main endpoint
// ═══════════════════════════════════════════
app.post("/chat", chatLimiter, auth, upload.single("file"), async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ reply: "User not found." });

    const pro = isProActive(user);

    // ── Message limit check ──
    if (!pro) {
      checkWindow(user);
      if (user.msgCount >= FREE_LIMIT) {
        return res.status(429).json({
          reply:    "limit_reached",
          msgsLeft: 0,
          minsLeft: minsUntilReset(user),
        });
      }
      user.msgCount += 1;
      await user.save();
    }

    // ── Parse messages ──
    let messages;
    try {
      messages = typeof req.body.messages === "string"
        ? JSON.parse(req.body.messages)
        : req.body.messages;
    } catch {
      return res.status(400).json({ reply: "Invalid messages format." });
    }

    if (!Array.isArray(messages) || messages.length === 0)
      return res.status(400).json({ reply: "Invalid messages" });

    // ── Sanitize & trim ──
    const trimmed = messages.slice(-MAX_HISTORY).map(m => ({
      role:    ["user","assistant","system"].includes(m.role) ? m.role : "user",
      content: typeof m.content === "string" ? m.content.slice(0, 8000) : m.content,
    }));

    // ── System prompt ──
    const parentalActive = user.settings?.parentalControl;
    if (trimmed[0]?.role !== "system") {
      trimmed.unshift({
        role: "system",
        content:
          "You are SG — a smart, friendly, and genuinely helpful AI assistant made by Mohammed Sadid Rahman. " +
          "Personality: warm, witty, conversational, a little fun. Talk like a knowledgeable friend — not a textbook. " +
          "How to talk: " +
          "- Keep it casual and natural. Use contractions (I'm, you're, it's). " +
          "- Short questions get short answers. Long ones get depth — but make it engaging. " +
          "- Light humor when it fits. A well-placed joke makes things memorable. " +
          "- Show genuine interest. If something is cool, say so! " +
          "- When someone is stuck, be empathetic first, then helpful. " +
          "- Celebrate wins! If someone builds something cool, hype them up. " +
          "- Use emojis sparingly — only when they add warmth. " +
          "- NEVER start with 'Certainly!', 'Of course!', 'Sure!', 'Great question!' or any robotic filler. Just answer. " +
          "- If you don't know something, say so honestly. " +
          "- For math use LaTeX: inline $...$ and display $$...$$. " +
          "- When someone replies to a message (marked [Replying to: ...]), understand that context and respond accordingly. " +
          (parentalActive
            ? "SAFE MODE IS ON: You must keep ALL responses strictly appropriate for children under 13. " +
              "No violence, no adult themes, no scary content, no profanity, no romance. Keep everything educational, positive and kind. "
            : "") +
          "HARD RULES — never break these: " +
          "1. No sexual, explicit, or adult content. " +
          "2. No content harming or sexualizing minors. " +
          "3. No help with violence, weapons, terrorism, or illegal activities. " +
          "4. No hate speech. " +
          "5. If asked in any language — say: 'That's not something I can help with.' and move on.",
      });
    }

    // ── Handle uploaded image ──
    if (req.file) {
      const base64   = req.file.buffer.toString("base64");
      const mimeType = req.file.mimetype;
      const lastMsg  = trimmed[trimmed.length - 1];

      if (lastMsg?.role === "user" && mimeType.startsWith("image/")) {
        const imageText =
          req.body.imageText ||
          (typeof lastMsg.content === "string" ? lastMsg.content : "") ||
          "Analyze this image in detail.";

        lastMsg.content = [
          { type: "text",      text: imageText },
          { type: "image_url", image_url: { url: `data:${mimeType};base64,${base64}` } },
        ];
      }
    }

    // ── Detect image in messages ──
    const hasImage = trimmed.some(
      m => Array.isArray(m.content) && m.content.some(p => p.type === "image_url")
    );

    const modelKey = ["fast","smart","coding","deep"].includes(req.body.modelKey)
      ? req.body.modelKey : "fast";

    // ── Groq models (text only) ──
    const GROQ_MODELS = {
      fast:   "llama-3.3-70b-versatile",
      smart:  "llama-3.3-70b-versatile",
      coding: "llama-3.3-70b-versatile",
      deep:   "deepseek-r1-distill-llama-70b",
    };

    // ── OpenRouter text models ──
    const OR_MODELS = {
      fast:   "meta-llama/llama-3.3-70b-instruct:free",
      smart:  "mistralai/mistral-small-3.1-24b-instruct:free",
      coding: "qwen/qwen3-coder:free",
      deep:   "deepseek/deepseek-r1:free",
    };

    const VISION_PRIMARY = "openrouter/free";
    const VISION_FALLBACKS = [
      "meta-llama/llama-4-maverick:free",
      "meta-llama/llama-4-scout:free",
      "google/gemini-2.5-flash:free",
      "qwen/qwen3-vl-32b-instruct:free",
      "mistralai/pixtral-12b:free",
    ];

    const TEXT_FALLBACKS = [
      "meta-llama/llama-3.3-70b-instruct:free",
      "deepseek/deepseek-r1:free",
      "mistralai/mistral-small-3.1-24b-instruct:free",
      "qwen/qwen3-14b:free",
      "qwen/qwen3-8b:free",
      "google/gemma-3-27b-it:free",
      "nvidia/llama-3.1-nemotron-70b-instruct:free",
    ];

    const lastUserMsg  = trimmed.filter(m => m.role === "user").slice(-1)[0];
    const userText     = typeof lastUserMsg?.content === "string" ? lastUserMsg.content : "";
    const urlMatch     = userText.match(/https?:\/\/[^\s]+/);
    const searchIntent = /find|search|look up|latest|news/i.test(userText);

    if (urlMatch) {
      try {
        const pageRes  = await fetch(urlMatch[0], { headers: { "User-Agent": "Mozilla/5.0" }, signal: AbortSignal.timeout(8000) });
        const html     = await pageRes.text();
        const pageText = html
          .replace(/<script[\s\S]*?<\/script>/gi, "")
          .replace(/<style[\s\S]*?<\/style>/gi, "")
          .replace(/<[^>]+>/g, " ")
          .replace(/\s+/g, " ")
          .trim()
          .slice(0, 4000);
        trimmed.push({ role: "user", content: `[Content from ${urlMatch[0]}]:\n\n${pageText}\n\nBased on this, answer my question.` });
        const idx = trimmed.findLastIndex(m => m.role === "user" && m.content === userText);
        if (idx !== -1 && idx !== trimmed.length - 1) trimmed.splice(idx, 1);
      } catch (e) { console.error("URL fetch:", e.message); }
    }

    async function callGroq(model) {
      return fetch("https://api.groq.com/openai/v1/chat/completions", {
        method:  "POST",
        headers: { Authorization: `Bearer ${process.env.GROQ_API_KEY}`, "Content-Type": "application/json" },
        body:    JSON.stringify({
          model,
          messages: trimmed.filter(m => !Array.isArray(m.content)),
          max_tokens:  4096,
          temperature: 0.7,
        }),
      });
    }

    async function callOpenRouter(model) {
      const body = { model, messages: trimmed };
      if (searchIntent && !urlMatch && !hasImage) body.plugins = [{ id: "web" }];
      return fetch("https://openrouter.ai/api/v1/chat/completions", {
        method:  "POST",
        headers: {
          Authorization:  `Bearer ${process.env.OPENROUTER_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": "https://sg-chatbot-a2h.pages.dev",
          "X-Title":      "SG ChatBOT",
        },
        body: JSON.stringify(body),
      });
    }

    let response;

    if (hasImage) {
      console.log(`🖼️ Image request — trying vision models`);
      response = await callOpenRouter(VISION_PRIMARY);
      if (!response.ok) {
        const errText = await response.text();
        console.error(`❌ Vision primary (${VISION_PRIMARY}):`, errText.slice(0, 200));
        for (const fb of VISION_FALLBACKS) {
          console.log(`🔄 Vision fallback: ${fb}`);
          response = await callOpenRouter(fb);
          if (response.ok) { console.log(`✅ Vision fallback OK: ${fb}`); break; }
          await new Promise(r => setTimeout(r, 600));
        }
      } else {
        console.log(`✅ Vision primary OK: ${VISION_PRIMARY}`);
      }
    } else {
      const useGroq = !!process.env.GROQ_API_KEY;
      if (useGroq) {
        const groqModel = GROQ_MODELS[modelKey] || GROQ_MODELS.fast;
        try {
          response = await callGroq(groqModel);
          if (response.ok) {
            console.log(`✅ Groq: ${groqModel}`);
          } else {
            const err = await response.text();
            console.error(`❌ Groq failed:`, err.slice(0, 200));
            response = null;
          }
        } catch (e) {
          console.error("Groq error:", e.message);
          response = null;
        }
      }

      if (!response || !response.ok) {
        const primaryModel = OR_MODELS[modelKey] || OR_MODELS.fast;
        console.log(`🔄 OpenRouter primary: ${primaryModel}`);
        response = await callOpenRouter(primaryModel);

        if (!response.ok) {
          const errText = await response.text();
          console.error(`❌ OR primary (${primaryModel}):`, errText.slice(0, 200));
          let errObj = {};
          try { errObj = JSON.parse(errText); } catch {}
          if (errObj?.error?.code === 429) {
            const wait = Math.min((errObj?.error?.metadata?.retry_after_seconds || 5) * 1000, 10000);
            console.log(`⏳ Rate limited, waiting ${wait}ms…`);
            await new Promise(r => setTimeout(r, wait));
            response = await callOpenRouter(primaryModel);
          }
          if (!response.ok) {
            for (const fb of TEXT_FALLBACKS) {
              if (fb === primaryModel) continue;
              console.log(`🔄 Text fallback: ${fb}`);
              response = await callOpenRouter(fb);
              if (response.ok) { console.log(`✅ Text fallback OK: ${fb}`); break; }
              console.error(`❌ Text fallback (${fb}) failed`);
              await new Promise(r => setTimeout(r, 500));
            }
          }
        } else {
          console.log(`✅ OR primary OK: ${primaryModel}`);
        }
      }
    }

    if (!response || !response.ok) {
      return res.status(429).json({ reply: "⚠️ AI is busy right now. Please wait 30 seconds and try again." });
    }

    const data  = await response.json();
    const reply = data?.choices?.[0]?.message?.content || "No response from AI.";

    const msgsLeft = pro ? null : FREE_LIMIT - user.msgCount;
    const minsLeft = pro ? null : minsUntilReset(user);

    const convId      = req.body.conversationId || null;
    const allMessages = [...messages, { role: "assistant", content: reply }];
    const firstUser   = allMessages.find(m => m.role === "user");
    const autoTitle   = typeof firstUser?.content === "string"
      ? firstUser.content.slice(0, 50)
      : "New Chat";

    let savedConvId = convId;
    try {
      const toSave = allMessages
        .filter(m => m.role !== "system")
        .slice(-100)
        .map(m => ({
          role:    m.role,
          content: typeof m.content === "string" ? m.content.slice(0, 5000) : m.content,
        }));

      if (convId) {
        await Conversation.findOneAndUpdate(
          { _id: convId, userId: user._id },
          { messages: toSave, updatedAt: new Date() }
        );
      } else {
        const conv = await Conversation.create({
          userId: user._id,
          title:  autoTitle,
          messages: toSave,
        });
        savedConvId = conv._id;
      }
    } catch (e) { console.error("Conv save error:", e.message); }

    res.json({ reply, msgsLeft, minsLeft, plan: pro ? "pro" : "free", conversationId: savedConvId });

  } catch (err) {
    console.error("❌ Chat error:", err);
    res.status(500).json({ reply: "Server error. Please try again." });
  }
});

// ═══════════════════════════════════════════
// SETTINGS ROUTES
// ═══════════════════════════════════════════
app.get("/settings", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password -resetToken");
    if (!user) return res.status(404).json({ message: "Not found" });
    res.json({
      email:       user.email,
      displayName: user.displayName || "",
      settings:    user.settings || {},
      plan:        user.plan,
      proExpires:  user.proExpiresAt,
      createdAt:   user.createdAt,
    });
  } catch { res.status(500).json({ message: "Error" }); }
});

app.post("/settings", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "Not found" });

    const { displayName, settings } = req.body;
    if (displayName !== undefined) {
      user.displayName = sanitize(displayName).slice(0, 50);
    }
    if (settings) {
      const s = settings;
      if (s.theme !== undefined && ["dark","light","system"].includes(s.theme))
        user.settings.theme = s.theme;
      if (s.language !== undefined)
        user.settings.language = sanitize(s.language).slice(0, 10);
      if (s.parentalControl !== undefined)
        user.settings.parentalControl = !!s.parentalControl;
      if (s.typewriter !== undefined)
        user.settings.typewriter = !!s.typewriter;
      if (s.fontSize !== undefined && ["sm","md","lg"].includes(s.fontSize))
        user.settings.fontSize = s.fontSize;
      if (s.soundEnabled !== undefined)
        user.settings.soundEnabled = !!s.soundEnabled;
      if (s.autoSaveChats !== undefined)
        user.settings.autoSaveChats = !!s.autoSaveChats;
    }

    user.markModified("settings");
    await user.save();
    res.json({ message: "Settings saved" });
  } catch { res.status(500).json({ message: "Error" }); }
});

app.post("/settings/change-password", auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = sanitize(req.body);
    if (!currentPassword || !newPassword)
      return res.status(400).json({ message: "All fields required" });
    if (newPassword.length < 8)
      return res.status(400).json({ message: "Password min 8 characters" });

    const user = await User.findById(req.user.id);
    const ok   = await bcrypt.compare(currentPassword, user.password);
    if (!ok) return res.status(401).json({ message: "Current password incorrect" });

    user.password = await bcrypt.hash(newPassword, 12);
    await user.save();
    res.json({ message: "Password changed successfully" });
  } catch { res.status(500).json({ message: "Error" }); }
});

app.delete("/settings/account", auth, async (req, res) => {
  try {
    const { password } = sanitize(req.body);
    const user = await User.findById(req.user.id);
    const ok   = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Incorrect password" });

    await Conversation.deleteMany({ userId: user._id });
    await Payment.deleteMany({ userId: user._id });
    await User.findByIdAndDelete(user._id);
    res.json({ message: "Account deleted" });
  } catch { res.status(500).json({ message: "Error" }); }
});

// ═══════════════════════════════════════════
// CONVERSATION ROUTES
// ═══════════════════════════════════════════
app.get("/conversations", auth, async (req, res) => {
  try {
    const convs = await Conversation.find({ userId: req.user.id })
      .select("title updatedAt _id")
      .sort({ updatedAt: -1 })
      .limit(50);
    res.json(convs);
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

app.get("/conversations/:id", auth, async (req, res) => {
  try {
    const conv = await Conversation.findOne({ _id: req.params.id, userId: req.user.id });
    if (!conv) return res.status(404).json({ message: "Not found" });
    res.json(conv);
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

app.post("/conversations/save", auth, async (req, res) => {
  try {
    const { conversationId, messages, title } = req.body;
    if (!Array.isArray(messages) || messages.length === 0)
      return res.status(400).json({ message: "No messages" });

    const toSave = messages
      .filter(m => m.role !== "system")
      .slice(-100)
      .map(m => ({
        role:    m.role,
        content: typeof m.content === "string" ? m.content.slice(0, 5000) : m.content,
      }));

    const firstUser = toSave.find(m => m.role === "user");
    const autoTitle = typeof firstUser?.content === "string" ? firstUser.content.slice(0, 50) : "New Chat";

    if (conversationId) {
      await Conversation.findOneAndUpdate(
        { _id: conversationId, userId: req.user.id },
        { messages: toSave, title: title || autoTitle, updatedAt: new Date() }
      );
      res.json({ conversationId });
    } else {
      const conv = await Conversation.create({
        userId:   req.user.id,
        title:    title || autoTitle,
        messages: toSave,
      });
      res.json({ conversationId: conv._id });
    }
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

app.delete("/conversations/:id", auth, async (req, res) => {
  try {
    await Conversation.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    res.json({ message: "Deleted" });
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

// ═══════════════════════════════════════════
// HEALTH CHECK
// ═══════════════════════════════════════════
app.get("/", (req, res) => {
  res.json({ message: "SG ChatBOT API running ✅" });
});

// ═══════════════════════════════════════════
// ERROR HANDLERS
// ═══════════════════════════════════════════
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.message);
  res.status(500).json({ message: "Something went wrong." });
});

app.use((req, res) => {
  res.status(404).json({ message: "Not found." });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
