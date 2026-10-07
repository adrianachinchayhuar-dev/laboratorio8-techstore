const db = require("../config/database");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

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

const loginUsuario = async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Validar campos
        if (!email || !password) {
            return res.status(400).json({
                mensaje: "Email y contraseña son obligatorios"
            });
        }

        // 2. Buscar usuario
        const [usuarios] = await db.query(
            "SELECT * FROM usuarios WHERE email = ?",
            [email]
        );

        if (usuarios.length === 0) {
            return res.status(401).json({
                mensaje: "Credenciales incorrectas"
            });
        }

        const usuario = usuarios[0];

        // 3. Verificar si está bloqueado
        if (usuario.bloqueado) {
            return res.status(403).json({
                mensaje: "Cuenta bloqueada por múltiples intentos fallidos"
            });
        }

        // 4. Comparar contraseña
        const passwordCorrecto = await bcrypt.compare(
            password,
            usuario.password
        );

        // 5. Contraseña incorrecta
        if (!passwordCorrecto) {

            const nuevosIntentos = usuario.intentos_fallidos + 1;

            if (nuevosIntentos >= 5) {

                await db.query(
                    `UPDATE usuarios
                     SET intentos_fallidos = ?, bloqueado = TRUE
                     WHERE id = ?`,
                    [nuevosIntentos, usuario.id]
                );

                return res.status(403).json({
                    mensaje:
                        "Cuenta bloqueada después de 5 intentos fallidos"
                });
            }

            await db.query(
                `UPDATE usuarios
                 SET intentos_fallidos = ?
                 WHERE id = ?`,
                [nuevosIntentos, usuario.id]
            );

            return res.status(401).json({
                mensaje: "Credenciales incorrectas",
                intentos_fallidos: nuevosIntentos,
                intentos_restantes: 5 - nuevosIntentos
            });
        }

        // 6. Login correcto: reiniciar intentos
        await db.query(
            `UPDATE usuarios
             SET intentos_fallidos = 0
             WHERE id = ?`,
            [usuario.id]
        );

        // 7. Generar JWT
        const token = jwt.sign(
            {
                id: usuario.id,
                email: usuario.email,
                rol: usuario.rol
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "1h"
            }
        );

        // 8. Respuesta
        return res.status(200).json({
            mensaje: "Inicio de sesión exitoso",
            token,
            usuario: {
                id: usuario.id,
                email: usuario.email,
                nombre_completo: usuario.nombre_completo,
                tienda: usuario.tienda,
                rol: usuario.rol
            }
        });

    } catch (error) {
        console.error("Error al iniciar sesión:", error);

        return res.status(500).json({
            mensaje: "Error interno del servidor"
        });
    }
};

module.exports = {
    registrarUsuario,
    loginUsuario
};