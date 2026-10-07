const express = require("express");

const router = express.Router();

const verificarToken =
    require("../middleware/authMiddleware");

const permitirRoles =
    require("../middleware/roleMiddleware");


// Cualquier usuario autenticado
router.get(
    "/perfil",
    verificarToken,
    (req, res) => {

        res.json({
            mensaje: "Acceso autorizado",
            usuario: req.usuario
        });
    }
);


// Solo administrador
router.get(
    "/admin",
    verificarToken,
    permitirRoles("ADMIN"),
    (req, res) => {

        res.json({
            mensaje: "Bienvenido al panel de administrador"
        });
    }
);


// Administrador y gerente
router.get(
    "/gestion-productos",
    verificarToken,
    permitirRoles("ADMIN", "GERENTE"),
    (req, res) => {

        res.json({
            mensaje: "Acceso a gestión de productos autorizado"
        });
    }
);


// Todos los perfiles pueden consultar productos
router.get(
    "/productos",
    verificarToken,
    permitirRoles(
        "ADMIN",
        "GERENTE",
        "VENTAS",
        "AUDITOR"
    ),
    (req, res) => {

        res.json({
            mensaje: "Consulta de productos autorizada"
        });
    }
);

module.exports = router;