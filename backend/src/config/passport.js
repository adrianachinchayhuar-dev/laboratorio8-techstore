const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const GitHubStrategy = require("passport-github2").Strategy;
const db = require("./database");

const findUserByEmail = async (email) => {
    const [usuarios] = await db.query(
        "SELECT * FROM usuarios WHERE email = ?",
        [email]
    );
    return usuarios[0] || null;
};

const registerGoogle = () => {
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) return false;
    passport.use("google", new GoogleStrategy({
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: process.env.GOOGLE_CALLBACK_URL || "http://localhost:3000/api/auth/google/callback"
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            const email = profile.emails?.[0]?.value;
            if (!email) return done(null, false, { message: "Google no proporcionó un correo electrónico" });
            return done(null, { provider: "GOOGLE", email, profile });
        } catch (error) { return done(error); }
    }));
    return true;
};

const registerGitHub = () => {
    if (!process.env.GITHUB_CLIENT_ID || !process.env.GITHUB_CLIENT_SECRET) return false;
    passport.use("github", new GitHubStrategy({
        clientID: process.env.GITHUB_CLIENT_ID,
        clientSecret: process.env.GITHUB_CLIENT_SECRET,
        callbackURL: process.env.GITHUB_CALLBACK_URL || "http://localhost:3000/api/auth/github/callback",
        scope: ["user:email"]
    }, async (accessToken, refreshToken, profile, done) => {
        try {
            const email = profile.emails?.find((item) => item.verified)?.value || profile.emails?.[0]?.value;
            if (!email) return done(null, false, { message: "GitHub no proporcionó un correo electrónico disponible" });
            return done(null, { provider: "GITHUB", email, profile });
        } catch (error) { return done(error); }
    }));
    return true;
};

const googleConfigured = registerGoogle();
const githubConfigured = registerGitHub();

module.exports = { passport, googleConfigured, githubConfigured, findUserByEmail };
