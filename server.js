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

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

dotenv.config({ path: path.join(__dirname, ".env") });

// ─────────────────────────────────────────
//  ENV VALIDATION
// ─────────────────────────────────────────
const REQUIRED_ENV = ["MONGO_URI", "OPENROUTER_KEY", "JWT_SECRET"];
for (const key of REQUIRED_ENV) {
  if (!process.env[key]) throw new Error(`Missing required env variable: ${key}`);
}

const JWT_SECRET  = process.env.JWT_SECRET;
const PORT        = process.env.PORT || 3000;
const MAX_HISTORY = 20;

// ─────────────────────────────────────────
//  APP SETUP
// ─────────────────────────────────────────
const app = express();

app.use(cors());
app.use(express.json({ limit: "16kb" }));
app.use(express.static(path.join(__dirname, "public")));

// ─────────────────────────────────────────
//  MULTER — memory storage (no disk files)
// ─────────────────────────────────────────
const ALLOWED_MIME_TYPES = [
  "image/jpeg", "image/png", "image/gif", "image/webp",
  "application/pdf",
  "application/msword",
  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
  "text/plain",
  "text/csv",
  "application/vnd.ms-excel",
  "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
];

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error(`Unsupported file type: ${file.mimetype}`));
    }
  },
});

// ─────────────────────────────────────────
//  RATE LIMITERS
// ─────────────────────────────────────────
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { message: "Too many attempts. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

const chatLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  message: { reply: "Rate limit exceeded. Please slow down." },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─────────────────────────────────────────
//  DATABASE
// ─────────────────────────────────────────
mongoose
  .connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });

// ─────────────────────────────────────────
//  USER SCHEMA
// ─────────────────────────────────────────
const userSchema = new mongoose.Schema(
  {
    email:    { type: String, required: true, unique: true, lowercase: true, trim: true },
    password: { type: String, required: true },
  },
  { timestamps: true }
);

const User = mongoose.model("User", userSchema);

// ─────────────────────────────────────────
//  HELPERS
// ─────────────────────────────────────────
function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

const IMAGE_MIME_TYPES = ["image/jpeg", "image/png", "image/gif", "image/webp"];

function isValidMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return false;
  return messages.every((m) => {
    if (!m || typeof m !== "object") return false;
    if (!["user", "assistant", "system"].includes(m.role)) return false;
    if (typeof m.content === "string") return m.content.trim().length > 0;
    if (Array.isArray(m.content)) return m.content.length > 0;
    return false;
  });
}

// ─────────────────────────────────────────
//  AUTH MIDDLEWARE
// ─────────────────────────────────────────
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ reply: "Authorization token missing." });
  }
  const token = header.slice(7).trim();
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ reply: "Invalid or expired token." });
  }
}

// ─────────────────────────────────────────
//  SIGNUP
// ─────────────────────────────────────────
app.post("/signup", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "Email and password are required." });

    const exists = await User.findOne({ email: email.toLowerCase().trim() });
    if (exists)
      return res.status(409).json({ message: "User already exists." });

    const hash = await bcrypt.hash(password, 12);
    await User.create({ email, password: hash });

    res.status(201).json({ message: "Account created." });
  } catch (err) {
    res.status(500).json({ message: "Server error." });
  }
});

// ─────────────────────────────────────────
//  LOGIN
// ─────────────────────────────────────────
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email: email.toLowerCase().trim() });

    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    const match = await bcrypt.compare(password, user.password);

    if (!match) return res.status(401).json({ message: "Invalid credentials" });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, email: user.email });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ─────────────────────────────────────────
//  CHAT
// ─────────────────────────────────────────
app.post("/chat", chatLimiter, auth, upload.single("file"), async (req, res) => {
  try {
    let messages = typeof req.body.messages === "string"
      ? JSON.parse(req.body.messages)
      : req.body.messages;

    if (!isValidMessages(messages))
      return res.status(400).json({ reply: "Invalid messages." });

    const trimmed = messages.slice(-MAX_HISTORY);

    const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.OPENROUTER_KEY}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "openai/gpt-4o-mini",
        messages: trimmed,
      }),
    });

    const data = await response.json();
    const reply = data?.choices?.[0]?.message?.content || "No response";

    res.json({ reply });
  } catch (err) {
    res.status(500).json({ reply: "Server error" });
  }
});

// ─────────────────────────────────────────
//  HEALTH
// ─────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

// ─────────────────────────────────────────
//  ROOT
// ─────────────────────────────────────────
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ─────────────────────────────────────────
//  START (FIXED HERE ✅)
// ─────────────────────────────────────────
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server running on http://0.0.0.0:${PORT}`);
});
