const db = require("../config/database");
const bcrypt = require("bcryptjs");

// Expresión regular:
// mínimo 8 caracteres
// al menos una mayúscula
// al menos un número
// al menos un carácter especial
const passwordRegex =
    /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/;

const registrarUsuario = async (req, res) => {
    try {
        const {
            email,
            password,
            nombre_completo,
            tienda,
            rol
        } = req.body;

        // 1. Validar campos obligatorios
        if (!email || !password || !nombre_completo || !tienda) {
            return res.status(400).json({
                mensaje: "Todos los campos son obligatorios"
            });
        }

        // 2. Validar contraseña
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                mensaje:
                    "La contraseña debe tener mínimo 8 caracteres, una mayúscula, un número y un carácter especial"
            });
        }

        // 3. Verificar si el correo ya existe
        const [usuariosExistentes] = await db.query(
            "SELECT id FROM usuarios WHERE email = ?",
            [email]
        );

        if (usuariosExistentes.length > 0) {
            return res.status(409).json({
                mensaje: "El correo electrónico ya está registrado"
            });
        }

        // 4. Cifrar contraseña
        const passwordHash = await bcrypt.hash(password, 10);

        // 5. Rol permitido
        const rolesPermitidos = [
            "ADMIN",
            "GERENTE",
            "VENTAS",
            "AUDITOR"
        ];

        const rolUsuario = rolesPermitidos.includes(rol)
            ? rol
            : "VENTAS";

        // 6. Guardar usuario
        const [resultado] = await db.query(
            `INSERT INTO usuarios
            (email, password, nombre_completo, tienda, rol)
            VALUES (?, ?, ?, ?, ?)`,
            [
                email,
                passwordHash,
                nombre_completo,
                tienda,
                rolUsuario
            ]
        );

        return res.status(201).json({
            mensaje: "Usuario registrado correctamente",
            usuario: {
                id: resultado.insertId,
                email,
                nombre_completo,
                tienda,
                rol: rolUsuario
            }
        });

    } catch (error) {
        console.error("Error al registrar usuario:", error);

        return res.status(500).json({
            mensaje: "Error interno del servidor"
        });
    }
};

module.exports = {
    registrarUsuario
};