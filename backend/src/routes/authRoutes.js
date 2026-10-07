const express = require("express");
const router = express.Router();

const {
    registrarUsuario,
    loginUsuario,
    configurarMFA,
    activarMFA,
    verificarMFA
} = require("../controllers/authController");

const verificarToken =
    require("../middleware/authMiddleware");

const {
    startGoogle,
    callbackGoogle,
    startGitHub,
    callbackGitHub
} = require("../controllers/oauthController");

router.get("/google", startGoogle);
router.get("/google/callback", callbackGoogle);
router.get("/github", startGitHub);
router.get("/github/callback", callbackGitHub);

router.post("/register", registrarUsuario);

router.post("/login", loginUsuario);

router.post(
    "/mfa/configurar",
    verificarToken,
    configurarMFA
);

router.post(
    "/mfa/activar",
    verificarToken,
    activarMFA
);

router.post(
    "/mfa/verificar",
    verificarMFA
);

module.exports = router;
