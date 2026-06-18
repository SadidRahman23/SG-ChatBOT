// config/passport.js
// Configures Passport's Google and GitHub OAuth2 strategies.
//
// Design notes:
// - We take the existing `User` Mongoose model as a parameter instead of importing/re-defining
//   it here, so this file has zero risk of duplicating the schema or creating a circular import
//   with server.js (per "no duplicated logic" / "preserve current architecture").
// - Every strategy uses { session: false } at the route level (see routes/oauth.js), so we never
//   call passport.serializeUser/deserializeUser — a JWT is minted immediately after a successful
//   OAuth callback and the app goes right back to its existing fully-stateless Bearer-token model.
//   express-session is only used transiently, to let the OAuth2 strategy store its CSRF `state`
//   value across the redirect to Google/GitHub and back.
// - A strategy is only registered if its env vars are present, so an app that hasn't configured
//   GitHub OAuth yet (for example) keeps working normally — Google login just won't be offered.
import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import { Strategy as GitHubStrategy } from "passport-github2";
import fetch from "node-fetch";
import bcrypt from "bcryptjs";
import crypto from "crypto";

// OAuth-created accounts get a random, never-disclosed password hash rather than a null password.
// This keeps the existing User schema's `password: { required: true }` invariant intact, so every
// other route that assumes `user.password` exists (change-password, etc.) keeps working unmodified.
async function randomUnusablePasswordHash() {
  return bcrypt.hash(crypto.randomBytes(24).toString("hex"), 12);
}

async function findOrLinkUser(User, { providerIdField, providerId, email, avatarUrl }) {
  let user = await User.findOne({ [providerIdField]: providerId });
  if (user) return user;

  if (email) {
    user = await User.findOne({ email });
    if (user) {
      user[providerIdField] = providerId;
      if (!user.avatarUrl && avatarUrl) user.avatarUrl = avatarUrl;
      await user.save();
      return user;
    }
  }

  if (!email) return null; // can't create an account with no identifiable email
  user = await User.create({
    email,
    password: await randomUnusablePasswordHash(),
    [providerIdField]: providerId,
    avatarUrl: avatarUrl || "",
  });
  return user;
}

export default function configurePassport(User) {
  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use("google", new GoogleStrategy({
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: `${process.env.APP_URL}/auth/google/callback`,
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value?.toLowerCase();
        if (!email) return done(null, false, { message: "Google account has no accessible email." });
        const user = await findOrLinkUser(User, {
          providerIdField: "googleId",
          providerId: profile.id,
          email,
          avatarUrl: profile.photos?.[0]?.value,
        });
        if (!user) return done(null, false, { message: "Could not create account." });
        user.lastLoginAt = new Date();
        await user.save();
        return done(null, user);
      } catch (err) { return done(err); }
    }));
  } else {
    console.warn("⚠️  GOOGLE_CLIENT_ID/SECRET not set — Google OAuth login is disabled.");
  }

  if (process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET) {
    passport.use("github", new GitHubStrategy({
      clientID: process.env.GITHUB_CLIENT_ID,
      clientSecret: process.env.GITHUB_CLIENT_SECRET,
      callbackURL: `${process.env.APP_URL}/auth/github/callback`,
      scope: ["user:email"],
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        // GitHub's profile object doesn't reliably include a *verified* email, so we fetch the
        // user's verified emails explicitly rather than trusting whatever passport-github2 attaches.
        let email = null;
        try {
          const r = await fetch("https://api.github.com/user/emails", {
            headers: { Authorization: `token ${accessToken}`, "User-Agent": "SG-ChatBOT-OAuth" },
          });
          if (r.ok) {
            const emails = await r.json();
            const best = emails.find(e => e.primary && e.verified) || emails.find(e => e.verified);
            if (best) email = best.email.toLowerCase();
          }
        } catch { /* fall through to profile.emails below */ }
        if (!email) email = profile.emails?.[0]?.value?.toLowerCase() || null;
        if (!email) return done(null, false, { message: "GitHub account has no verified email." });

        const user = await findOrLinkUser(User, {
          providerIdField: "githubId",
          providerId: profile.id,
          email,
          avatarUrl: profile.photos?.[0]?.value,
        });
        if (!user) return done(null, false, { message: "Could not create account." });
        user.lastLoginAt = new Date();
        await user.save();
        return done(null, user);
      } catch (err) { return done(err); }
    }));
  } else {
    console.warn("⚠️  GITHUB_CLIENT_ID/SECRET not set — GitHub OAuth login is disabled.");
  }

  return passport;
}
