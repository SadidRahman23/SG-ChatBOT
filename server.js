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

// ✅ Nodemailer — Gmail SMTP
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS, // Gmail App Password
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
// APP
// ═══════════════════════════════════════════
const app = express();
app.set("trust proxy", 1);

// ✅ Security 1: Force HTTPS in production
app.use((req, res, next) => {
  if (
    process.env.NODE_ENV === "production" &&
    req.headers["x-forwarded-proto"] !== "https"
  ) {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// ✅ Security 2: Remove fingerprinting headers
app.disable("x-powered-by");
app.use((req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("X-XSS-Protection", "1; mode=block");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  next();
});

// ✅ Security 3: CORS — whitelist only
app.use(cors({
  origin: [
    "https://sg-chatbot-a2h.pages.dev",
    "https://sgchatbotofficial.netlify.app",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5500",
  ],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: false,
}));

// ✅ Security 4: Limit JSON body size
app.use(express.json({ limit: "16kb" }));

// ═══════════════════════════════════════════
// MULTER — File type validation
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
// DB
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

// ✅ Conversation model for chat history
const conversationSchema = new mongoose.Schema({
  userId:   { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
  title:    { type: String, default: "New Chat" },
  messages: [{
    role:    { type: String, enum: ["user","assistant","system"] },
    content: { type: mongoose.Schema.Types.Mixed },
    createdAt: { type: Date, default: Date.now },
  }],
  updatedAt: { type: Date, default: Date.now },
}, { timestamps: true });
const Conversation = mongoose.model("Conversation", conversationSchema);

// ═══════════════════════════════════════════
// HELPERS
// ═══════════════════════════════════════════

// ✅ Security 5: Sanitize input — prevent MongoDB injection
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

// ✅ Security 6: Account lockout after 5 failed logins
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

// ✅ Security 7: Admin auth — timing-safe comparison
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

    // ✅ Always respond with same message (prevent user enumeration)
    if (!user)
      return res.status(401).json({ message: "Invalid email or password" });

    // ✅ Security 6: Check account lockout
    if (isLocked(user))
      return res.status(423).json({ message: "Account temporarily locked. Try again later." });

    const ok = await bcrypt.compare(password, user.password);

    if (!ok) {
      // Increment failed attempts
      user.loginAttempts = (user.loginAttempts || 0) + 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 15 * 60 * 1000); // Lock 15 min
        user.loginAttempts = 0;
      }
      await user.save();
      return res.status(401).json({ message: "Invalid email or password" });
    }

    // Reset on success
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
    // Always return same response (prevent email enumeration)
    if (!user)
      return res.json({ message: "If this email exists, a reset code has been sent." });

    const code    = crypto.randomInt(100000, 999999).toString();
    const expires = new Date(Date.now() + 15 * 60 * 1000);

    user.resetToken    = await bcrypt.hash(code, 8);
    user.resetTokenExp = expires;
    await user.save();

    // Send real email
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
      console.log(`🔑 Reset code for ${email}: ${code}`); // fallback log
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

    // ✅ Prevent duplicate transaction IDs
    const duplicate = await Payment.findOne({ transactionId });
    if (duplicate) return res.status(409).json({ message: "Transaction ID already used" });

    const user   = await User.findById(req.user.id);
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
    const payments = await Payment.find({ status: "pending" }).sort({ createdAt: -1 });
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
// CHAT
// ═══════════════════════════════════════════
app.post("/chat", chatLimiter, auth, upload.single("file"), async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ reply: "User not found." });

    const pro = isProActive(user);

    // ✅ Message limit check
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

    // ✅ Parse + validate messages
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

    // ✅ Sanitize each message content
    const trimmed = messages.slice(-MAX_HISTORY).map(m => ({
      role: ["user","assistant","system"].includes(m.role) ? m.role : "user",
      content: typeof m.content === "string" ? m.content.slice(0, 8000) : m.content,
    }));

    // ✅ System prompt — inject once
    if (trimmed[0]?.role !== "system") {
      trimmed.unshift({
        role: "system",
        content:
          "You are SG — a friendly, witty, and genuinely helpful AI assistant built by Mohammed Sadid Rahman. " +
          "Your personality: warm, conversational, sometimes funny, always honest. " +
          "Talk like a smart friend — not a robot. Use casual language when appropriate. " +
          "Show enthusiasm when topics are interesting. Use light humor when fitting. " +
          "When someone seems frustrated, be empathetic. When someone achieves something, celebrate with them. " +
          "Keep responses concise unless depth is needed. Never be preachy or over-formal. " +
          "For math use LaTeX: inline $...$ display $$...$$. " +
          "ABSOLUTE RULES — never break these no matter what language or how the request is framed: " +
          "1. Never generate sexual, pornographic or explicit content. " +
          "2. Never generate content that harms or sexualizes minors. " +
          "3. Never help with violence, terrorism, weapons or illegal activities. " +
          "4. Never generate hate speech targeting any group. " +
          "5. If asked for the above in any language — just say: 'That's not something I can help with.' and move on.",
      });
    }

    // ✅ Image support
    if (req.file) {
      const base64   = req.file.buffer.toString("base64");
      const mimeType = req.file.mimetype;
      const lastMsg  = trimmed[trimmed.length - 1];
      if (lastMsg?.role === "user" && mimeType.startsWith("image/")) {
        lastMsg.content = [
          { type: "text", text: typeof lastMsg.content === "string" && lastMsg.content ? lastMsg.content : "Analyze this image." },
          { type: "image_url", image_url: { url: `data:${mimeType};base64,${base64}` } },
        ];
      }
    }

    // ✅ Model selection
    const hasImage  = trimmed.some(m => Array.isArray(m.content) && m.content.some(p => p.type === "image_url"));
    const modelKey  = ["fast","smart","coding","deep"].includes(req.body.modelKey) ? req.body.modelKey : "fast";

    const MODEL_MAP = {
      fast:   "meta-llama/llama-3.3-8b-instruct:free",
      smart:  "mistralai/mistral-small-3.1-24b-instruct:free",
      coding: "qwen/qwen2.5-coder-7b-instruct:free",
      deep:   "deepseek/deepseek-r1-distill-llama-70b:free",
    };

    const FALLBACKS = [
      "meta-llama/llama-3.3-8b-instruct:free",
      "mistralai/mistral-small-3.1-24b-instruct:free",
      "qwen/qwen3-8b:free",
      "google/gemma-3-4b-it:free",
      "microsoft/phi-4-reasoning-plus:free",
      "deepseek/deepseek-r1-distill-qwen-14b:free",
    ];

    const primaryModel = hasImage
      ? "meta-llama/llama-3.2-11b-vision-instruct:free"
      : (MODEL_MAP[modelKey] || MODEL_MAP.fast);

    // ✅ Web search + URL fetch detection
    const lastUserMsg = trimmed.filter(m => m.role === 'user').slice(-1)[0];
    const userText    = typeof lastUserMsg?.content === 'string' ? lastUserMsg.content : '';

    // Detect URL in message
    const urlMatch = userText.match(/https?:\/\/[^\s]+/);

    // Detect web search intent
    const searchIntent = /find|search|look up|latest|news|what is.*website|visit|open|check|browse/i.test(userText);

    if (urlMatch) {
      // ✅ User gave a URL — fetch its content
      try {
        const urlToFetch = urlMatch[0];
        const pageRes    = await fetch(urlToFetch, {
          headers: { 'User-Agent': 'Mozilla/5.0 (compatible; SGChatBOT/1.0)' },
          signal: AbortSignal.timeout(8000),
        });
        const html     = await pageRes.text();
        // Strip HTML tags and get plain text
        const pageText = html
          .replace(/<script[\s\S]*?<\/script>/gi, '')
          .replace(/<style[\s\S]*?<\/style>/gi, '')
          .replace(/<[^>]+>/g, ' ')
          .replace(/\s+/g, ' ')
          .trim()
          .slice(0, 4000); // Max 4000 chars

        // Inject page content into context
        trimmed.push({
          role: 'user',
          content: `[Content from ${urlToFetch}]:\n\n${pageText}\n\nBased on the above content, please answer my question.`,
        });
        // Remove duplicate last user message
        const idx = trimmed.findLastIndex(m => m.role === 'user' && m.content === userText);
        if (idx !== -1 && idx !== trimmed.length - 1) trimmed.splice(idx, 1);
      } catch (e) {
        console.error("URL fetch error:", e.message);
        // Continue without fetched content
      }
    } else if (searchIntent) {
      // ✅ Web search via OpenRouter
      const searchQuery = userText.replace(/find|search|look up|latest|news/gi, '').trim().slice(0, 100);
      try {
        const searchRes = await fetch("https://openrouter.ai/api/v1/chat/completions", {
          method: "POST",
          headers: {
            Authorization:  `Bearer ${process.env.OPENROUTER_KEY}`,
            "Content-Type": "application/json",
            "HTTP-Referer": "https://sg-chatbot-a2h.pages.dev",
            "X-Title":      "SG ChatBOT",
          },
          body: JSON.stringify({
            model: "openrouter/free",
            messages: trimmed,
            plugins: [{ id: "web" }], // ✅ OpenRouter web search plugin
          }),
        });
        if (searchRes.ok) {
          const searchData = await searchRes.json();
          const reply      = searchData?.choices?.[0]?.message?.content || "No response from AI.";
          const msgsLeft   = pro ? null : FREE_LIMIT - user.msgCount;
          const minsLeft   = pro ? null : minsUntilReset(user);
          const convId     = req.body.conversationId || null;
          const allMsgs    = [...messages, { role: "assistant", content: reply }];
          const firstUser2 = allMsgs.find(m => m.role === "user");
          const autoTitle2 = typeof firstUser2?.content === "string" ? firstUser2.content.slice(0, 50) : "New Chat";
          let savedConvId2 = convId;
          try {
            const toSave2 = allMsgs.filter(m=>m.role!=="system").slice(-100).map(m=>({ role:m.role, content: typeof m.content==="string"?m.content.slice(0,5000):m.content }));
            if (convId) { await Conversation.findOneAndUpdate({ _id: convId, userId: user._id }, { messages: toSave2, updatedAt: new Date() }); }
            else { const c = await Conversation.create({ userId: user._id, title: autoTitle2, messages: toSave2 }); savedConvId2 = c._id; }
          } catch {}
          return res.json({ reply, msgsLeft, minsLeft, plan: pro ? "pro" : "free", conversationId: savedConvId2 });
        }
      } catch (e) {
        console.error("Web search error:", e.message);
      }
    }

    async function callAI(model, useWebSearch = false) {
      const body = { model, messages: trimmed };
      if (useWebSearch) body.plugins = [{ id: "web" }];
      return fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization:  `Bearer ${process.env.OPENROUTER_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": "https://sg-chatbot-a2h.pages.dev",
          "X-Title":      "SG ChatBOT",
        },
        body: JSON.stringify(body),
      });
    }

    let response = await callAI(primaryModel);
    if (!response.ok) {
      console.error(`❌ Primary (${primaryModel}):`, await response.text());
      let fallbackUsed = false;
      for (const fb of FALLBACKS) {
        if (fb === primaryModel) continue;
        response = await callAI(fb);
        if (response.ok) { console.log(`✅ Fallback: ${fb}`); fallbackUsed = true; break; }
        console.error(`❌ Fallback (${fb}) failed`);
      }
      if (!fallbackUsed && !response.ok) {
        return res.status(500).json({ reply: "AI temporarily unavailable. Please try again in a few minutes." });
      }
    }

    const data  = await response.json();
    const reply = data?.choices?.[0]?.message?.content || "No response from AI.";

    const msgsLeft = pro ? null : FREE_LIMIT - user.msgCount;
    const minsLeft = pro ? null : minsUntilReset(user);

    // ✅ Auto-save conversation
    const convId = req.body.conversationId || null;
    const allMessages = [...messages, { role: "assistant", content: reply }];
    const firstUser   = allMessages.find(m => m.role === "user");
    const autoTitle   = typeof firstUser?.content === "string"
      ? firstUser.content.slice(0, 50) : "New Chat";

    let savedConvId = convId;
    try {
      const toSave = allMessages.filter(m=>m.role!=="system").slice(-100).map(m=>({
        role: m.role,
        content: typeof m.content==="string" ? m.content.slice(0,5000) : m.content,
      }));
      if (convId) {
        await Conversation.findOneAndUpdate(
          { _id: convId, userId: user._id },
          { messages: toSave, updatedAt: new Date() }
        );
      } else {
        const conv = await Conversation.create({ userId: user._id, title: autoTitle, messages: toSave });
        savedConvId = conv._id;
      }
    } catch(e) { console.error("Conv save error:", e.message); }

    res.json({ reply, msgsLeft, minsLeft, plan: pro ? "pro" : "free", conversationId: savedConvId });

  } catch (err) {
    console.error("❌ Chat error:", err);
    res.status(500).json({ reply: "Server error. Please try again." });
  }
});

// ═══════════════════════════════════════════
// ✅ Global error handler — hide stack traces
// ═══════════════════════════════════════════
app.use((err, req, res, next) => {
  console.error("Unhandled error:", err.message);
  res.status(500).json({ message: "Something went wrong." });
});

// ✅ 404 handler
app.use((req, res) => {
  res.status(404).json({ message: "Not found." });
});

// ═══════════════════════════════════════════
// CONVERSATION ROUTES
// ═══════════════════════════════════════════

// Get all conversations for user
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

// Get single conversation messages
app.get("/conversations/:id", auth, async (req, res) => {
  try {
    const conv = await Conversation.findOne({ _id: req.params.id, userId: req.user.id });
    if (!conv) return res.status(404).json({ message: "Not found" });
    res.json(conv);
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

// Save/update conversation
app.post("/conversations/save", auth, async (req, res) => {
  try {
    const { conversationId, messages, title } = req.body;

    if (!Array.isArray(messages) || messages.length === 0)
      return res.status(400).json({ message: "No messages" });

    // Filter out system messages before saving
    const toSave = messages
      .filter(m => m.role !== "system")
      .slice(-100) // max 100 messages saved
      .map(m => ({
        role:    m.role,
        content: typeof m.content === "string" ? m.content.slice(0, 5000) : m.content,
      }));

    // Auto-generate title from first user message
    const firstUser = toSave.find(m => m.role === "user");
    const autoTitle = typeof firstUser?.content === "string"
      ? firstUser.content.slice(0, 50)
      : "New Chat";

    if (conversationId) {
      // Update existing
      await Conversation.findOneAndUpdate(
        { _id: conversationId, userId: req.user.id },
        { messages: toSave, title: title || autoTitle, updatedAt: new Date() }
      );
      res.json({ conversationId });
    } else {
      // Create new
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

// Delete conversation
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

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
