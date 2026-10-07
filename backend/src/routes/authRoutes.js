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