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

app.use(cors({
  origin: [
    "https://sgchatbotofficial.netlify.app",
    "http://localhost:3000",
    "http://127.0.0.1:5500",
  ],
}));
app.use(express.json({ limit: "16kb" }));

// ─────────────────────────────────────────
//  MULTER — memory storage (no disk files)
// ─────────────────────────────────────────
const ALLOWED_MIME_TYPES = [
  // Images
  "image/jpeg", "image/png", "image/gif", "image/webp",
  // Documents
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
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB max
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

// Validate messages — now supports both string and array content (vision)
function isValidMessages(messages) {
  if (!Array.isArray(messages) || messages.length === 0) return false;
  return messages.every((m) => {
    if (!m || typeof m !== "object") return false;
    if (!["user", "assistant", "system"].includes(m.role)) return false;
    // Content can be a string OR an array (vision messages)
    if (typeof m.content === "string") return m.content.trim().length > 0;
    if (Array.isArray(m.content))      return m.content.length > 0;
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
    const message =
      err.name === "TokenExpiredError"
        ? "Session expired. Please log in again."
        : "Invalid token.";
    return res.status(401).json({ reply: message });
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
    if (!isValidEmail(email))
      return res.status(400).json({ message: "Invalid email format." });
    if (password.length < 8 || password.length > 128)
      return res.status(400).json({ message: "Password must be 8–128 characters." });

    const exists = await User.findOne({ email: email.toLowerCase().trim() });
    if (exists)
      return res.status(409).json({ message: "An account with this email already exists." });

    const hash = await bcrypt.hash(password, 12);
    await User.create({ email, password: hash });

    res.status(201).json({ message: "Account created successfully." });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Server error during signup." });
  }
});

// ─────────────────────────────────────────
//  LOGIN
// ─────────────────────────────────────────
app.post("/login", authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ message: "Email and password are required." });
    if (!isValidEmail(email))
      return res.status(400).json({ message: "Invalid email format." });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    const dummyHash = "$2a$12$invalidhashfortimingprotectiononly.......";
    const passwordToCheck = user ? user.password : dummyHash;
    const match = await bcrypt.compare(password, passwordToCheck);

    if (!user || !match)
      return res.status(401).json({ message: "Invalid email or password." });

    const token = jwt.sign(
      { id: user._id, email: user.email },
      JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token, email: user.email });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error during login." });
  }
});

// ─────────────────────────────────────────
//  CHAT  (supports text + file uploads)
// ─────────────────────────────────────────
app.post(
  "/chat",
  chatLimiter,
  auth,
  upload.single("file"),   // optional file field named "file"
  async (req, res) => {
    try {
      // Messages arrive as JSON string in FormData OR as parsed JSON body
      let messages;
      try {
        messages = typeof req.body.messages === "string"
          ? JSON.parse(req.body.messages)
          : req.body.messages;
      } catch {
        return res.status(400).json({ reply: "Invalid messages format." });
      }

      if (!isValidMessages(messages))
        return res.status(400).json({ reply: "Invalid or empty message history." });

      // ── If a file was uploaded, rebuild the last user message ──
      if (req.file) {
        const fileType = req.body.fileType || "document"; // "image" | "document"
        const base64   = req.file.buffer.toString("base64");
        const mime     = req.file.mimetype;
        const filename = req.file.originalname;

        // Find the last user message and enrich it
        const lastUserIdx = [...messages].reverse().findIndex(m => m.role === "user");
        if (lastUserIdx !== -1) {
          const realIdx = messages.length - 1 - lastUserIdx;
          const existing = messages[realIdx];

          if (IMAGE_MIME_TYPES.includes(mime)) {
            // Vision-capable model — send image inline
            const textPart = typeof existing.content === "string" && existing.content.trim()
              ? existing.content
              : "Please analyze this image and describe what you see in detail.";

            messages[realIdx] = {
              role: "user",
              content: [
                { type: "text", text: textPart },
                { type: "image_url", image_url: { url: `data:${mime};base64,${base64}` } },
              ],
            };
          } else {
            // Non-image document — prepend filename note to text
            const originalText = typeof existing.content === "string"
              ? existing.content
              : "";
            const docNote = `[Attached document: ${filename}]\n\n`;
            messages[realIdx] = {
              role: "user",
              content: docNote + (originalText || "Please analyze this document and summarize its contents."),
            };
          }
        }
      }

      const trimmed = messages.slice(-MAX_HISTORY);

      // Use gpt-4o (vision) when images present, gpt-4o-mini otherwise
      const hasImage = trimmed.some(
        m => Array.isArray(m.content) &&
             m.content.some(p => p.type === "image_url")
      );
      const model = hasImage ? "openai/gpt-4o" : "openai/gpt-4o-mini";

      const response = await fetch("https://openrouter.ai/api/v1/chat/completions", {
        method: "POST",
        headers: {
          Authorization: `Bearer ${process.env.OPENROUTER_KEY}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ model, messages: trimmed }),
      });

      const data  = await response.json();
      const reply = data?.choices?.[0]?.message?.content || "No response from AI.";

      res.json({ reply });
    } catch (err) {
      console.error("Chat error:", err);
      res.status(500).json({ reply: "Server error. Please try again." });
    }
  }
);

// ─────────────────────────────────────────
//  MULTER ERROR HANDLER
// ─────────────────────────────────────────
app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE")
      return res.status(400).json({ reply: "File too large. Maximum size is 10 MB." });
    return res.status(400).json({ reply: `Upload error: ${err.message}` });
  }
  if (err && err.message && err.message.startsWith("Unsupported file type")) {
    return res.status(400).json({ reply: err.message });
  }
  next(err);
});

// ─────────────────────────────────────────
//  HEALTH
// ─────────────────────────────────────────
app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    db: mongoose.connection.readyState === 1 ? "connected" : "disconnected",
  });
});

// ─────────────────────────────────────────
//  ROOT
// ─────────────────────────────────────────
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ─────────────────────────────────────────
//  404
// ─────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ message: "Route not found." });
});

// ─────────────────────────────────────────
//  START
// ─────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`🚀 Server running on http://localhost:${PORT}`);
});
