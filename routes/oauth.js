// routes/oauth.js
// Exposes exactly the four routes requested:
//   GET /auth/google            GET /auth/google/callback
//   GET /auth/github            GET /auth/github/callback
//
// On success, mints the SAME kind of JWT the existing /login route issues (same secret, same
// expiry, same payload shape: { id }), so every existing authenticated route keeps working
// unchanged for OAuth-logged-in users — they're indistinguishable from password-login users to
// the rest of the app. The token is delivered to the frontend via a redirect (?token=...) since
// this is a full-page browser navigation, not an API call the SPA can read a JSON body from.
import express from "express";
import passport from "passport";
import jwt from "jsonwebtoken";

const FRONTEND_URL = process.env.FRONTEND_URL || "https://sg-chatbot-a2h.pages.dev";

function issueTokenAndRedirect(req, res) {
  if (!req.user) return res.redirect(`${FRONTEND_URL}/login?error=oauth_failed`);
  const token = jwt.sign({ id: req.user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
  res.redirect(`${FRONTEND_URL}/oauth-callback?token=${token}`);
}

export default function createOAuthRouter() {
  const router = express.Router();

  const googleEnabled = !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET);
  const githubEnabled = !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET);

  // Initial redirect — must NOT have session:false so passport-oauth2 can store its CSRF `state`
  // in the session. Without this, the callback has nothing to verify against and throws
  // "Failed to obtain access token".
  router.get("/auth/google", (req, res, next) => {
    if (!googleEnabled) return res.status(503).json({ message: "Google login is not configured on this server." });
    passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
  });

  // Callback — session:false here so no persistent user session is created; we mint a JWT instead.
  router.get("/auth/google/callback", (req, res, next) => {
    if (!googleEnabled) return res.status(503).json({ message: "Google login is not configured on this server." });
    passport.authenticate("google", { session: false, failureRedirect: `${FRONTEND_URL}/login?error=google_oauth_failed` })(req, res, next);
  }, issueTokenAndRedirect);

  // Same pattern for GitHub
  router.get("/auth/github", (req, res, next) => {
    if (!githubEnabled) return res.status(503).json({ message: "GitHub login is not configured on this server." });
    passport.authenticate("github", { scope: ["user:email"] })(req, res, next);
  });

  router.get("/auth/github/callback", (req, res, next) => {
    if (!githubEnabled) return res.status(503).json({ message: "GitHub login is not configured on this server." });
    passport.authenticate("github", { session: false, failureRedirect: `${FRONTEND_URL}/login?error=github_oauth_failed` })(req, res, next);
  }, issueTokenAndRedirect);

  return router;
}
