require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const crypto = require("crypto");
const fetch = require("node-fetch");

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static("."));

// ==========================================
// 1. RATE LIMITING MIDDLEWARE
// ==========================================
const rateLimit = {};
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
// 2. MONGODB CONNECTION & SCHEMAS
// ==========================================
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch(err => console.error("MongoDB connection error:", err));

const UserSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
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
// 3. IP BAN MIDDLEWARE (FIXED: Admin Bypass)
// ==========================================
app.use(async (req, res, next) => {
  // Admin route গুলো ban check থেকে skip করবে, যাতে ব্লকড থাকলেও আনব্লক করা যায়
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
// 4. HELPER FUNCTIONS & AI LOGIC (FIXED: Scoping & Sanitization)
// ==========================================

// FIXED: Removed '$' from regex so users can use $ in passwords
function sanitize(input) {
  if (typeof input === "string") return input.replace(/[\x00]/g, "").trim().slice(0, 1000);
  return input;
}

const GROQ_KEYS = (process.env.GROQ_API_KEYS || "").split(",").map(k => k.trim()).filter(Boolean);
const GOOGLE_MODELS = { "gemini-flash": "gemini-1.5-flash", "gemini-pro": "gemini-1.5-pro" };

// FIXED: Moved outside of /chat so /chat/stream can access them
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
  // OpenRouter or other alternative fallback logic
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
      
      // FIXED: resilient error handling
      if (r.status === 429) continue;
      if (!r.ok) continue; // Changed from 'return false' to 'continue'
      
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

// ==========================================
// 5. ADMIN ROUTES
// ==========================================
app.post("/api/admin/verify", (req, res) => {
  const { secret } = req.body;
  const adminSecret = process.env.ADMIN_SECRET;
  if (!secret) return res.status(400).json({ success: false, error: "Secret required" });
  try {
    if (secret.length !== adminSecret.length || !crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(adminSecret))) {
      return res.status(401).json({ success: false, error: "Wrong secret" });
    }
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: "Internal server error" });
  }
});

app.post("/api/admin/ban", async (req, res) => {
  const { secret, ip, reason } = req.body;
  const adminSecret = process.env.ADMIN_SECRET;
  if (!secret || secret.length !== adminSecret.length || !crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(adminSecret))) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
  try {
    await Ban.findOneAndUpdate({ ip }, { ip, reason }, { upsert: true, returnDocument: 'after' });
    res.json({ success: true, message: "IP banned successfully" });
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to ban IP" });
  }
});

app.post("/api/admin/unban", async (req, res) => {
  const { secret, ip } = req.body;
  const adminSecret = process.env.ADMIN_SECRET;
  if (!secret || secret.length !== adminSecret.length || !crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(adminSecret))) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
  try {
    await Ban.deleteOne({ ip });
    res.json({ success: true, message: "IP unbanned successfully" });
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to unban IP" });
  }
});

app.post("/api/admin/banned-ips", async (req, res) => {
  const { secret } = req.body;
  const adminSecret = process.env.ADMIN_SECRET;
  if (!secret || secret.length !== adminSecret.length || !crypto.timingSafeEqual(Buffer.from(secret), Buffer.from(adminSecret))) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }
  try {
    const list = await Ban.find({});
    res.json({ success: true, banned: list });
  } catch (err) {
    res.status(500).json({ success: false, error: "Failed to fetch list" });
  }
});

// ==========================================
// 6. AUTHENTICATION & SETTINGS ROUTES
// ==========================================
app.post("/signup", async (req, res) => {
  const email = sanitize(req.body.email);
  const password = sanitize(req.body.password);
  if (!email || !password) return res.status(400).json({ success: false, error: "All fields required" });
  try {
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ success: false, error: "User already exists" });
    await User.create({ email, password });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: "Signup failed" });
  }
});

app.post("/login", async (req, res) => {
  const email = sanitize(req.body.email);
  const password = sanitize(req.body.password);
  try {
    const user = await User.findOne({ email, password });
    if (!user) return res.status(401).json({ success: false, error: "Invalid email or password" });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ success: false, error: "Login failed" });
  }
});

app.post("/settings/change-password", async (req, res) => {
  const email = sanitize(req.body.email);
  const oldPassword = sanitize(req.body.oldPassword);
  const newPassword = sanitize(req.body.newPassword);
  try {
    const user = await User.findOne({ email, password: oldPassword });
    if (!user) return res.status(401).json({ success: false, error: "Authentication failed" });
    user.password = newPassword;
    await user.save();
    res.json({ success: true, message: "Password updated" });
  } catch (err) {
    res.status(500).json({ success: false, error: "Server error" });
  }
});

// ==========================================
// 7. CHAT & STREAMING ROUTES
// ==========================================
app.post("/chat", async (req, res) => {
  const { messages, model, modelKey } = req.body;
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
    
    // Default to Groq
    const text = await callGroqRotating(model, messages);
    res.json({ response: text });

  } catch (err) {
    res.status(500).json({ success: false, error: "Chat failed" });
  }
});

app.post("/chat/stream", async (req, res) => {
  const { messages, model, modelKey } = req.body;
  try {
    const success = await tryGroqStream(messages, model, res);
    
    // Fallback logic if Groq streaming fails
    if (!success) {
      if (modelKey && GOOGLE_MODELS[modelKey]) {
        const text = await callGoogle(GOOGLE_MODELS[modelKey], messages);
        res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: text } }] })}\n\n`);
        res.end();
      } else if (modelKey && modelKey.startsWith("mistral")) {
        const text = await callMistral(model, messages);
        res.write(`data: ${JSON.stringify({ choices: [{ delta: { content: text } }] })}\n\n`);
        res.end();
      } else {
        res.status(500).send("Streaming failed across all channels.");
      }
    }
  } catch (err) {
    if (!res.writableEnded) res.status(500).send("Stream error");
  }
});

// ==========================================
// 8. SERVER START
// ==========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
