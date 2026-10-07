const jwt = require("jsonwebtoken");
const db = require("../config/database");
const { googleConfigured, githubConfigured } = require("../config/passport");

const frontendUrl = (name, fallback) => process.env[name] || fallback;
const redirectWithError = (res, message) => {
    const target = new URL(frontendUrl("FRONTEND_LOGIN_URL", "http://localhost:3000/login.html"));
    target.searchParams.set("oauth_error", message);
    return res.redirect(target.toString());
};

const getUserColumns = async () => {
    const [columns] = await db.query("SHOW COLUMNS FROM usuarios");
    return new Map(columns.map((column) => [column.Field, column]));
};

const createSocialUser = async ({ provider, email, profile }) => {
    const columns = await getUserColumns();
    if (!columns.has("proveedor")) {
        throw new Error("La tabla usuarios necesita una columna proveedor para habilitar usuarios OAuth");
    }
    if (columns.get("password").Null !== "YES") {
        throw new Error("La columna password debe permitir NULL para usuarios OAuth");
    }

    const name = profile.displayName || profile.username || email.split("@")[0];
    const [result] = await db.query(
        `INSERT INTO usuarios (email, password, nombre_completo, tienda, rol, proveedor)
         VALUES (?, NULL, ?, ?, 'VENTAS', ?)`,
        [email, name, "Tienda Lima", provider]
    );
    return {
        id: result.insertId,
        email,
        nombre_completo: name,
        tienda: "Tienda Lima",
        rol: "VENTAS",
        mfa_habilitado: false
    };
};

const issueToken = (usuario, pendingMfa = false) => jwt.sign(
    pendingMfa
        ? { id: usuario.id, tipo: "MFA_PENDING" }
        : { id: usuario.id, email: usuario.email, nombre_completo: usuario.nombre_completo, tienda: usuario.tienda, rol: usuario.rol, mfa_habilitado: Boolean(usuario.mfa_habilitado) },
    process.env.JWT_SECRET,
    { expiresIn: pendingMfa ? "5m" : "1h" }
);

const finishOAuth = async (req, res, provider) => {
    try {
        if (!req.user) return redirectWithError(res, "No se pudo obtener el perfil del proveedor");
        const { email, profile } = req.user;
        let usuario = await require("../config/passport").findUserByEmail(email);
        if (!usuario) usuario = await createSocialUser({ provider, email, profile });

        if (usuario.mfa_habilitado) {
            const tokenTemporal = issueToken(usuario, true);
            const target = new URL(frontendUrl("FRONTEND_MFA_URL", "http://localhost:3000/mfa.html"));
            target.hash = new URLSearchParams({ token_temporal: tokenTemporal }).toString();
            return res.redirect(target.toString());
        }

        const token = issueToken(usuario);
        const target = new URL(frontendUrl("FRONTEND_DASHBOARD_URL", "http://localhost:3000/dashboard.html"));
        target.hash = new URLSearchParams({ token }).toString();
        return res.redirect(target.toString());
    } catch (error) {
        console.error(`Error en OAuth ${provider}:`, error.message);
        return redirectWithError(res, "No se pudo completar el inicio de sesión social");
    }
};

const startGoogle = (req, res, next) => {
    if (!googleConfigured) return res.status(503).json({ mensaje: "Google OAuth no está configurado" });
    return require("../config/passport").passport.authenticate("google", { scope: ["profile", "email"], session: false })(req, res, next);
};
const callbackGoogle = (req, res, next) => {
    if (!googleConfigured) return res.status(503).json({ mensaje: "Google OAuth no está configurado" });
    return require("../config/passport").passport.authenticate("google", { session: false }, (error, user, info) => {
        if (error) return next(error);
        if (!user) return redirectWithError(res, info?.message || "Google no pudo autenticar la cuenta");
        req.user = user;
        return finishOAuth(req, res, "GOOGLE");
    })(req, res, next);
};
const startGitHub = (req, res, next) => {
    if (!githubConfigured) return res.status(503).json({ mensaje: "GitHub OAuth no está configurado" });
    return require("../config/passport").passport.authenticate("github", { scope: ["user:email"], session: false })(req, res, next);
};
const callbackGitHub = (req, res, next) => {
    if (!githubConfigured) return res.status(503).json({ mensaje: "GitHub OAuth no está configurado" });
    return require("../config/passport").passport.authenticate("github", { session: false }, (error, user, info) => {
        if (error) return next(error);
        if (!user) return redirectWithError(res, info?.message || "GitHub no pudo autenticar la cuenta");
        req.user = user;
        return finishOAuth(req, res, "GITHUB");
    })(req, res, next);
};

module.exports = { startGoogle, callbackGoogle, startGitHub, callbackGitHub };
