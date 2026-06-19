// routes/oauth.js
// Manual OAuth implementation — no passport dependency for the actual token exchange.
// Passport had persistent "Failed to obtain access token" issues; direct fetch calls
// to GitHub/Google token endpoints are simpler, easier to debug, and more reliable.
import express from "express";
import fetch   from "node-fetch";
import jwt     from "jsonwebtoken";
import crypto  from "crypto";

const FRONTEND_URL = process.env.FRONTEND_URL || "https://sg-chatbot-a2h.pages.dev";
const APP_URL      = process.env.APP_URL      || "https://sg-chatbot-z8hp.onrender.com";

// In-memory state store (CSRF protection). State entries expire after 10 minutes.
// On Render free tier a single instance is always running, so this is safe;
// if you later scale to multiple instances, replace with a Redis/MongoDB store.
const stateStore = new Map();
function newState() {
  const s = crypto.randomBytes(18).toString("hex");
  stateStore.set(s, Date.now());
  return s;
}
function verifyState(s) {
  const ts = stateStore.get(s);
  stateStore.delete(s);
  return ts && (Date.now() - ts) < 10 * 60 * 1000;
}

function issueJWT(userId) {
  return jwt.sign({ id: userId }, process.env.JWT_SECRET, { expiresIn: "7d" });
}

export default function createOAuthRouter({ User }) {
  const router = express.Router();

  const githubOK = !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET);
  const googleOK = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);

  // ── GITHUB ──────────────────────────────────────────────────────────────────
  router.get("/auth/github", (req, res) => {
    if (!githubOK) return res.status(503).json({ message: "GitHub login is not configured." });
    const state = newState();
    const params = new URLSearchParams({
      client_id:    process.env.GITHUB_CLIENT_ID,
      redirect_uri: `${APP_URL}/auth/github/callback`,
      scope:        "user:email",
      state,
    });
    res.redirect(`https://github.com/login/oauth/authorize?${params}`);
  });

  router.get("/auth/github/callback", async (req, res) => {
    const fail = (reason) => {
      console.error("GitHub OAuth failed:", reason);
      return res.redirect(`${FRONTEND_URL}/oauth-callback?error=github_oauth_failed`);
    };

    const { code, state, error } = req.query;
    if (error)            return fail(`GitHub error: ${error}`);
    if (!code)            return fail("No code received");
    if (!verifyState(state)) return fail("Invalid or expired state");

    try {
      // 1. Exchange code for access token
      const tokenRes = await fetch("https://github.com/login/oauth/access_token", {
        method:  "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body:    JSON.stringify({
          client_id:     process.env.GITHUB_CLIENT_ID,
          client_secret: process.env.GITHUB_CLIENT_SECRET,
          code,
          redirect_uri:  `${APP_URL}/auth/github/callback`,
        }),
        signal: AbortSignal.timeout(10000),
      });
      const tokenData = await tokenRes.json();
      console.log("GitHub token response:", JSON.stringify(tokenData));  // logs actual GitHub error if any

      if (tokenData.error || !tokenData.access_token) {
        return fail(`Token error: ${tokenData.error} — ${tokenData.error_description || ""}`);
      }

      const accessToken = tokenData.access_token;
      console.log("GitHub: fetching profile and emails...");

      // 2. Get GitHub user profile
      const [profileRes, emailsRes] = await Promise.all([
        fetch("https://api.github.com/user",        { headers: { Authorization: `Bearer ${accessToken}`, "User-Agent": "SG-ChatBOT" }, signal: AbortSignal.timeout(8000) }),
        fetch("https://api.github.com/user/emails", { headers: { Authorization: `Bearer ${accessToken}`, "User-Agent": "SG-ChatBOT" }, signal: AbortSignal.timeout(8000) }),
      ]);

      const profile = await profileRes.json();
      const emails  = await emailsRes.json();
      console.log("GitHub profile id:", profile.id, "login:", profile.login);
      console.log("GitHub emails:", JSON.stringify(emails));

      const primaryEmail = Array.isArray(emails)
        ? (emails.find(e => e.primary && e.verified) || emails.find(e => e.verified))?.email?.toLowerCase()
        : null;
      const email = primaryEmail || profile.email?.toLowerCase() || null;
      console.log("GitHub resolved email:", email);

      if (!email) return fail("No verified email on GitHub account");

      // 3. Find or create user
      console.log("GitHub: finding/creating user for email:", email);
      let user = await User.findOne({ githubId: String(profile.id) });
      if (!user) {
        user = await User.findOne({ email });
        if (user) {
          console.log("GitHub: linking existing user", user._id);
          user.githubId = String(profile.id);
          if (!user.avatarUrl && profile.avatar_url) user.avatarUrl = profile.avatar_url;
        } else {
          console.log("GitHub: creating new user");
          const bcrypt = (await import("bcryptjs")).default;
          const crypto2 = (await import("crypto")).default;
          user = new User({
            email,
            password:  await bcrypt.hash(crypto2.randomBytes(24).toString("hex"), 12),
            githubId:  String(profile.id),
            avatarUrl: profile.avatar_url || "",
          });
        }
      } else {
        console.log("GitHub: found existing user by githubId", user._id);
      }
      user.lastLoginAt = new Date();
      await user.save();
      console.log("GitHub: user saved, id:", user._id);

      // 4. Mint JWT and redirect to frontend
      const token = issueJWT(user._id);
      const redirectUrl = `${FRONTEND_URL}/oauth-callback?token=${token}`;
      console.log("GitHub: redirecting to", redirectUrl.replace(token, "[TOKEN]"));
      return res.redirect(redirectUrl);

    } catch (err) {
      return fail(err.message);
    }
  });

  // ── GOOGLE ──────────────────────────────────────────────────────────────────
  router.get("/auth/google", (req, res) => {
    if (!googleOK) return res.status(503).json({ message: "Google login is not configured." });
    const state = newState();
    const params = new URLSearchParams({
      client_id:     process.env.GOOGLE_CLIENT_ID,
      redirect_uri:  `${APP_URL}/auth/google/callback`,
      response_type: "code",
      scope:         "openid email profile",
      access_type:   "offline",
      state,
    });
    res.redirect(`https://accounts.google.com/o/oauth2/v2/auth?${params}`);
  });

  router.get("/auth/google/callback", async (req, res) => {
    const fail = (reason) => {
      console.error("Google OAuth failed:", reason);
      return res.redirect(`${FRONTEND_URL}/oauth-callback?error=google_oauth_failed`);
    };

    const { code, state, error } = req.query;
    if (error)               return fail(`Google error: ${error}`);
    if (!code)               return fail("No code received");
    if (!verifyState(state)) return fail("Invalid or expired state");

    try {
      // 1. Exchange code for tokens
      const tokenRes = await fetch("https://oauth2.googleapis.com/token", {
        method:  "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body:    new URLSearchParams({
          code,
          client_id:     process.env.GOOGLE_CLIENT_ID,
          client_secret: process.env.GOOGLE_CLIENT_SECRET,
          redirect_uri:  `${APP_URL}/auth/google/callback`,
          grant_type:    "authorization_code",
        }),
        signal: AbortSignal.timeout(10000),
      });
      const tokenData = await tokenRes.json();
      if (tokenData.error || !tokenData.access_token) {
        return fail(`Token error: ${tokenData.error}`);
      }

      // 2. Get user info
      const infoRes = await fetch("https://www.googleapis.com/oauth2/v2/userinfo", {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
        signal: AbortSignal.timeout(8000),
      });
      const profile = await infoRes.json();
      if (!profile.email) return fail("No email on Google account");

      const email = profile.email.toLowerCase();

      // 3. Find or create user
      let user = await User.findOne({ googleId: String(profile.id) });
      if (!user) {
        user = await User.findOne({ email });
        if (user) {
          user.googleId = String(profile.id);
          if (!user.avatarUrl && profile.picture) user.avatarUrl = profile.picture;
        } else {
          const bcrypt = (await import("bcryptjs")).default;
          const crypto2 = (await import("crypto")).default;
          user = new User({
            email,
            password:  await bcrypt.hash(crypto2.randomBytes(24).toString("hex"), 12),
            googleId:  String(profile.id),
            avatarUrl: profile.picture || "",
          });
        }
      }
      user.lastLoginAt = new Date();
      await user.save();

      const token = issueJWT(user._id);
      return res.redirect(`${FRONTEND_URL}/oauth-callback?token=${token}`);

    } catch (err) {
      return fail(err.message);
    }
  });

  return router;
}
