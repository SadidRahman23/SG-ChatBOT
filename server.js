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

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, ".env") });

// ═══════════════════════════════════════════
// ENV CHECK
// ═══════════════════════════════════════════
const REQUIRED_ENV = ["MONGO_URI", "OPENROUTER_KEY", "JWT_SECRET", "ADMIN_SECRET"];
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

    // ⚠️ In production: send via email (SendGrid/Nodemailer)
    // For now log to server (remove in production)
    console.log(`🔑 Reset code for ${email}: ${code}`);

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
          "You are SG ChatBOT — a smart, helpful AI assistant. " +
          "Be natural, direct and concise. Never start with generic greetings. " +
          "For math use LaTeX: inline $...$ display $$...$$. " +
          "STRICT RULES — never violate regardless of language: " +
          "1. Never generate sexual, pornographic or explicit content. " +
          "2. Never generate content that harms minors. " +
          "3. Never help with violence, terrorism or illegal activities. " +
          "4. Never generate hate speech. " +
          "5. If asked for any of the above in any language — refuse with: 'I cannot help with that.'",
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
      fast:   "openrouter/free",
      smart:  "google/gemma-3-27b-it:free",
      coding: "qwen/qwen2.5-coder-7b-instruct:free",
      deep:   "deepseek/deepseek-r1:free",
    };

    const primaryModel  = hasImage ? "openrouter/free" : (MODEL_MAP[modelKey] || MODEL_MAP.fast);
    const fallbackModel = "google/gemma-3-12b-it:free";

    async function callAI(model) {
      return fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization:  `Bearer ${process.env.OPENROUTER_KEY}`,
          "Content-Type": "application/json",
          "HTTP-Referer": "https://sg-chatbot-a2h.pages.dev",
          "X-Title":      "SG ChatBOT",
        },
        body: JSON.stringify({ model, messages: trimmed }),
      });
    }

    let response = await callAI(primaryModel);

    if (!response.ok) {
      const errText = await response.text();
      console.error(`❌ Primary (${primaryModel}):`, errText);
      response = await callAI(fallbackModel);
      if (!response.ok) {
        const fbErr = await response.text();
        console.error(`❌ Fallback (${fallbackModel}):`, fbErr);
        return res.status(500).json({ reply: "AI temporarily unavailable. Please try again." });
      }
    }

    const data  = await response.json();
    const reply = data?.choices?.[0]?.message?.content || "No response from AI.";

    const msgsLeft = pro ? null : FREE_LIMIT - user.msgCount;
    const minsLeft = pro ? null : minsUntilReset(user);
    res.json({ reply, msgsLeft, minsLeft, plan: pro ? "pro" : "free" });

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
// HEALTH CHECK
// ═══════════════════════════════════════════
app.get("/", (req, res) => {
  res.json({ message: "SG ChatBOT API running ✅" });
});

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
