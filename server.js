import express from "express";
import mongoose from "mongoose";
import fetch from "node-fetch";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import path from "path";
import rateLimit from "express-rate-limit";
import multer from "multer";
import { fileURLToPath } from "url";

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
dotenv.config({ path: path.join(__dirname, ".env") });

// ─────────────────────────────────────────
// ENV CHECK
// ─────────────────────────────────────────
const REQUIRED_ENV = ["MONGO_URI", "OPENROUTER_KEY", "JWT_SECRET"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) throw new Error(`Missing env: ${key}`);
}

const JWT_SECRET   = process.env.JWT_SECRET;
const ADMIN_SECRET = process.env.ADMIN_SECRET || "sgadmin2025"; // change this!
const PORT         = process.env.PORT || 3000;
const MAX_HISTORY  = 20;
const FREE_LIMIT   = 25;          // messages per 4 hours for free users
const FREE_WINDOW  = 4 * 60 * 60 * 1000; // 4 hours in milliseconds

// ─────────────────────────────────────────
// APP
// ─────────────────────────────────────────
const app = express();
app.set("trust proxy", 1);

app.use(cors({
  origin: [
    "https://sgchatbotofficial.netlify.app",
    "https://sg-chatbot-a2h.pages.dev",
    "http://localhost:3000",
    "http://localhost:5173",
    "http://127.0.0.1:5500",
  ],
  methods: ["GET", "POST", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

app.use(express.json({ limit: "16kb" }));

// ─────────────────────────────────────────
// MULTER
// ─────────────────────────────────────────
const storage = multer.memoryStorage();
const upload  = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

// ─────────────────────────────────────────
// RATE LIMIT
// ─────────────────────────────────────────
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
const chatLimiter = rateLimit({ windowMs: 60 * 1000, max: 30 });

// ─────────────────────────────────────────
// DB
// ─────────────────────────────────────────
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => { console.error("❌ MongoDB failed:", err.message); process.exit(1); });

// ─────────────────────────────────────────
// MODELS
// ─────────────────────────────────────────
const userSchema = new mongoose.Schema({
  email:        { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:     { type: String, required: true },
  plan:         { type: String, enum: ["free", "pro"], default: "free" },
  proExpiresAt: { type: Date, default: null },
  msgCount:     { type: Number, default: 0 },       // messages in current window
  msgWindowStart: { type: Date, default: null },     // when current 4h window started
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

// Payment request model
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

// ─────────────────────────────────────────
// AUTH MIDDLEWARE
// ─────────────────────────────────────────
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
  const secret = req.headers["x-admin-secret"];
  if (secret !== ADMIN_SECRET)
    return res.status(403).json({ message: "Forbidden" });
  next();
}

// ─────────────────────────────────────────
// HELPERS
// ─────────────────────────────────────────
function isProActive(user) {
  if (user.plan !== "pro") return false;
  if (!user.proExpiresAt) return false;
  return new Date() < new Date(user.proExpiresAt);
}

// Reset counter if 4h window expired
function checkWindow(user) {
  const now = Date.now();
  if (!user.msgWindowStart || (now - new Date(user.msgWindowStart).getTime()) >= FREE_WINDOW) {
    user.msgCount       = 0;
    user.msgWindowStart = new Date();
  }
}

// Minutes until window resets
function minsUntilReset(user) {
  if (!user.msgWindowStart) return 0;
  const elapsed = Date.now() - new Date(user.msgWindowStart).getTime();
  const ms      = Math.max(0, FREE_WINDOW - elapsed);
  return Math.ceil(ms / 60000);
}

// ─────────────────────────────────────────
// SIGNUP
// ─────────────────────────────────────────
app.post("/signup", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Email and password required" });

    const exists = await User.findOne({ email });
    if (exists) return res.status(409).json({ message: "User already exists" });

    const hash = await bcrypt.hash(password, 12);
    await User.create({ email, password: hash });
    res.json({ message: "Account created" });
  } catch {
    res.status(500).json({ message: "Signup error" });
  }
});

// ─────────────────────────────────────────
// LOGIN
// ─────────────────────────────────────────
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(401).json({ message: "Invalid login" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: "Invalid login" });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ token });
  } catch {
    res.status(500).json({ message: "Login error" });
  }
});

// ─────────────────────────────────────────
// GET USER STATUS (plan, messages left)
// ─────────────────────────────────────────
app.get("/status", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });

    const pro = isProActive(user);
    checkWindow(user);

    const msgsLeft  = pro ? null : Math.max(0, FREE_LIMIT - user.msgCount);
    const minsLeft  = pro ? null : minsUntilReset(user);

    res.json({
      email:      user.email,
      plan:       pro ? "pro" : "free",
      msgsLeft,
      freeLimit:  FREE_LIMIT,
      minsLeft,   // minutes until window resets
      proExpires: user.proExpiresAt,
    });
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

// ─────────────────────────────────────────
// SUBMIT PAYMENT
// ─────────────────────────────────────────
app.post("/payment/submit", auth, async (req, res) => {
  try {
    const { method, transactionId, plan } = req.body;

    if (!method || !transactionId || !plan)
      return res.status(400).json({ message: "Missing fields" });

    if (!["bkash", "nagad"].includes(method))
      return res.status(400).json({ message: "Invalid method" });

    if (!["monthly", "yearly"].includes(plan))
      return res.status(400).json({ message: "Invalid plan" });

    // Check duplicate transaction ID
    const duplicate = await Payment.findOne({ transactionId });
    if (duplicate)
      return res.status(409).json({ message: "Transaction ID already used" });

    const amount = plan === "monthly" ? 99 : 799;

    const user = await User.findById(req.user.id);

    await Payment.create({
      userId:        user._id,
      email:         user.email,
      method,
      transactionId,
      amount,
      plan,
      status:        "pending",
    });

    res.json({ message: "Payment submitted! We will verify within 24 hours." });
  } catch {
    res.status(500).json({ message: "Payment submission error" });
  }
});

// ─────────────────────────────────────────
// ADMIN — View pending payments
// ─────────────────────────────────────────
app.get("/admin/payments", adminAuth, async (req, res) => {
  try {
    const payments = await Payment.find({ status: "pending" }).sort({ createdAt: -1 });
    res.json(payments);
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

// ─────────────────────────────────────────
// ADMIN — Approve payment → activate Pro
// ─────────────────────────────────────────
app.post("/admin/approve/:paymentId", adminAuth, async (req, res) => {
  try {
    const payment = await Payment.findById(req.params.paymentId);
    if (!payment) return res.status(404).json({ message: "Payment not found" });

    payment.status = "approved";
    await payment.save();

    // Activate Pro for user
    const user = await User.findById(payment.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    const now     = new Date();
    const expires = new Date(now);

    if (payment.plan === "monthly") {
      expires.setMonth(expires.getMonth() + 1);
    } else {
      expires.setFullYear(expires.getFullYear() + 1);
    }

    user.plan         = "pro";
    user.proExpiresAt = expires;
    await user.save();

    res.json({ message: `Pro activated for ${user.email} until ${expires.toDateString()}` });
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

// ─────────────────────────────────────────
// ADMIN — Reject payment
// ─────────────────────────────────────────
app.post("/admin/reject/:paymentId", adminAuth, async (req, res) => {
  try {
    const payment = await Payment.findById(req.params.paymentId);
    if (!payment) return res.status(404).json({ message: "Payment not found" });

    payment.status = "rejected";
    await payment.save();

    res.json({ message: "Payment rejected" });
  } catch {
    res.status(500).json({ message: "Error" });
  }
});

// ─────────────────────────────────────────
// CHAT
// ─────────────────────────────────────────
app.post("/chat", chatLimiter, auth, upload.single("file"), async (req, res) => {
  try {

    // ── Check message limit ──
    const user  = await User.findById(req.user.id);
    if (!user) return res.status(401).json({ reply: "User not found." });

    const pro = isProActive(user);

    if (!pro) {
      checkWindow(user); // reset if 4h passed

      if (user.msgCount >= FREE_LIMIT) {
        return res.status(429).json({
          reply:     "limit_reached",
          msgsLeft:  0,
          freeLimit: FREE_LIMIT,
          minsLeft:  minsUntilReset(user),
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

    const trimmed = messages.slice(-MAX_HISTORY);

    // ── System prompt ──
    if (trimmed[0]?.role !== "system") {
      trimmed.unshift({
        role: "system",
        content:
          "You are SG ChatBOT — a smart, helpful AI assistant built by Mohammed Sadid Rahman. " +
          "Be natural, direct and concise. Never start with generic greetings. " +
          "Answer the user's question immediately and clearly.",
      });
    }

    // ── Image support ──
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

    // ── Model selection ──
    const hasImage = trimmed.some(
      m => Array.isArray(m.content) && m.content.some(p => p.type === "image_url")
    );

    const primaryModel  = hasImage ? "qwen/qwen2.5-vl-72b-instruct:free" : "openrouter/free";
    const fallbackModel = hasImage ? "qwen/qwen2.5-vl-7b-instruct:free"  : "qwen/qwen3-8b:free";

    // ── OpenRouter call ──
    async function callOpenRouter(model) {
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

    let response = await callOpenRouter(primaryModel);

    if (!response.ok) {
      const errText = await response.text();
      console.error(`❌ Primary (${primaryModel}) failed:`, errText);

      response = await callOpenRouter(fallbackModel);
      if (!response.ok) {
        const fbErr = await response.text();
        console.error(`❌ Fallback (${fallbackModel}) failed:`, fbErr);
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

// ─────────────────────────────────────────
// HEALTH CHECK
// ─────────────────────────────────────────
app.get("/", (req, res) => {
  res.json({ message: "SG ChatBOT API running ✅" });
});

// ─────────────────────────────────────────
// SERVER START
// ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
