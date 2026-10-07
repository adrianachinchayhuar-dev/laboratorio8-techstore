const db = require("../config/database");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const speakeasy = require("speakeasy");
const QRCode = require("qrcode");

// =====================================================
// VALIDACIÓN DE CONTRASEÑA
// Mínimo 8 caracteres
// Al menos una mayúscula
// Al menos un número
// Al menos un carácter especial
// =====================================================

const passwordRegex =
    /^(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/;


// =====================================================
// REGISTRO DE USUARIO
// =====================================================

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

        // 5. Validar rol
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


// =====================================================
// LOGIN
// =====================================================

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
                mensaje:
                    "Cuenta bloqueada por múltiples intentos fallidos"
            });
        }

        // 4. Comparar contraseña
        const passwordCorrecto = await bcrypt.compare(
            password,
            usuario.password
        );

        // 5. Contraseña incorrecta
        if (!passwordCorrecto) {

            const nuevosIntentos =
                usuario.intentos_fallidos + 1;

            // Bloquear después de 5 intentos
            if (nuevosIntentos >= 5) {

                await db.query(
                    `UPDATE usuarios
                     SET intentos_fallidos = ?,
                         bloqueado = TRUE
                     WHERE id = ?`,
                    [
                        nuevosIntentos,
                        usuario.id
                    ]
                );

                return res.status(403).json({
                    mensaje:
                        "Cuenta bloqueada después de 5 intentos fallidos"
                });
            }

            // Incrementar intentos fallidos
            await db.query(
                `UPDATE usuarios
                 SET intentos_fallidos = ?
                 WHERE id = ?`,
                [
                    nuevosIntentos,
                    usuario.id
                ]
            );

            return res.status(401).json({
                mensaje: "Credenciales incorrectas",
                intentos_fallidos: nuevosIntentos,
                intentos_restantes:
                    5 - nuevosIntentos
            });
        }

        // 6. Contraseña correcta:
        // reiniciar intentos fallidos
        await db.query(
            `UPDATE usuarios
             SET intentos_fallidos = 0
             WHERE id = ?`,
            [usuario.id]
        );


        // =================================================
        // 7. COMPROBAR SI EL USUARIO TIENE MFA
        // =================================================

        if (usuario.mfa_habilitado) {

            // Reiniciar intentos MFA
            // al iniciar un nuevo proceso de login
            await db.query(
                `UPDATE usuarios
                 SET intentos_mfa = 0
                 WHERE id = ?`,
                [usuario.id]
            );

            // Crear token temporal.
            // Este token NO permite acceso completo.
            const tokenTemporal = jwt.sign(
                {
                    id: usuario.id,
                    tipo: "MFA_PENDING"
                },
                process.env.JWT_SECRET,
                {
                    expiresIn: "5m"
                }
            );

            return res.status(200).json({
                mensaje:
                    "Credenciales correctas. Se requiere código MFA",
                requiere_mfa: true,
                token_temporal: tokenTemporal
            });
        }


        // =================================================
        // 8. SI NO TIENE MFA, GENERAR JWT NORMAL
        // =================================================

        const token = jwt.sign(
            {
                id: usuario.id,
                email: usuario.email,
                rol: usuario.rol,
                mfa_habilitado: Boolean(usuario.mfa_habilitado)
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "1h"
            }
        );


        // 9. Respuesta
        return res.status(200).json({
            mensaje: "Inicio de sesión exitoso",
            requiere_mfa: false,
            token,
            usuario: {
                id: usuario.id,
                email: usuario.email,
                nombre_completo:
                    usuario.nombre_completo,
                tienda: usuario.tienda,
                rol: usuario.rol,
                mfa_habilitado: Boolean(usuario.mfa_habilitado)
            }
        });

    } catch (error) {
        console.error(
            "Error al iniciar sesión:",
            error
        );

        return res.status(500).json({
            mensaje: "Error interno del servidor"
        });
    }
};


// =====================================================
// CONFIGURAR MFA
// =====================================================

const configurarMFA = async (req, res) => {
    try {

        const usuarioId = req.usuario.id;

        // Buscar usuario
        const [usuarios] = await db.query(
            "SELECT * FROM usuarios WHERE id = ?",
            [usuarioId]
        );

        if (usuarios.length === 0) {
            return res.status(404).json({
                mensaje: "Usuario no encontrado"
            });
        }

        const usuario = usuarios[0];

        // Generar secreto TOTP
        const secret =
            speakeasy.generateSecret({
                name:
                    `TechStore (${usuario.email})`
            });

        // Guardar secreto en la BD
        await db.query(
            `UPDATE usuarios
             SET mfa_secret = ?
             WHERE id = ?`,
            [
                secret.base32,
                usuarioId
            ]
        );

        // Generar QR
        const qrCode =
            await QRCode.toDataURL(
                secret.otpauth_url
            );

        return res.status(200).json({
            mensaje:
                "Escanea el código QR con Google Authenticator",
            qrCode
        });

    } catch (error) {

        console.error(
            "Error configurando MFA:",
            error
        );

        return res.status(500).json({
            mensaje:
                "Error al configurar MFA"
        });
    }
};


// =====================================================
// ACTIVAR MFA
// =====================================================

const activarMFA = async (req, res) => {
    try {

        const usuarioId =
            req.usuario.id;

        const { codigo } = req.body;

        // Validar código
        if (!codigo) {
            return res.status(400).json({
                mensaje:
                    "El código MFA es obligatorio"
            });
        }

        // Buscar usuario
        const [usuarios] =
            await db.query(
                "SELECT * FROM usuarios WHERE id = ?",
                [usuarioId]
            );

        if (usuarios.length === 0) {
            return res.status(404).json({
                mensaje:
                    "Usuario no encontrado"
            });
        }

        const usuario = usuarios[0];

        // Verificar que primero haya configurado MFA
        if (!usuario.mfa_secret) {
            return res.status(400).json({
                mensaje:
                    "Primero debes configurar MFA"
            });
        }

        // Verificar código TOTP
        const codigoValido =
            speakeasy.totp.verify({
                secret:
                    usuario.mfa_secret,
                encoding: "base32",
                token: codigo,
                window: 1
            });

        if (!codigoValido) {
            return res.status(400).json({
                mensaje:
                    "Código MFA incorrecto"
            });
        }

        // Activar MFA
        await db.query(
            `UPDATE usuarios
             SET mfa_habilitado = TRUE,
                 intentos_mfa = 0
             WHERE id = ?`,
            [usuarioId]
        );

        return res.status(200).json({
            mensaje:
                "MFA activado correctamente"
        });

    } catch (error) {

        console.error(
            "Error activando MFA:",
            error
        );

        return res.status(500).json({
            mensaje:
                "Error al activar MFA"
        });
    }
};


// =====================================================
// VERIFICAR MFA DURANTE EL LOGIN
// =====================================================

const verificarMFA = async (req, res) => {
    try {

        const {
            codigo,
            token_temporal
        } = req.body;

        // Validar datos
        if (!codigo || !token_temporal) {
            return res.status(400).json({
                mensaje:
                    "Código MFA y token temporal son obligatorios"
            });
        }


        // =============================================
        // VERIFICAR TOKEN TEMPORAL
        // =============================================

        let decoded;

        try {

            decoded = jwt.verify(
                token_temporal,
                process.env.JWT_SECRET
            );

        } catch (error) {

            return res.status(401).json({
                mensaje:
                    "Token temporal inválido o expirado"
            });
        }


        // Verificar que sea específicamente
        // un token pendiente de MFA
        if (decoded.tipo !== "MFA_PENDING") {

            return res.status(401).json({
                mensaje:
                    "Token temporal inválido"
            });
        }


        // =============================================
        // BUSCAR USUARIO
        // =============================================

        const [usuarios] =
            await db.query(
                "SELECT * FROM usuarios WHERE id = ?",
                [decoded.id]
            );

        if (usuarios.length === 0) {

            return res.status(404).json({
                mensaje:
                    "Usuario no encontrado"
            });
        }

        const usuario = usuarios[0];


        // =============================================
        // COMPROBAR INTENTOS MFA
        // =============================================

        if (usuario.intentos_mfa >= 3) {

            return res.status(403).json({
                mensaje:
                    "Máximo de intentos MFA alcanzado"
            });
        }


        // =============================================
        // VERIFICAR CÓDIGO TOTP
        // =============================================

        const codigoValido =
            speakeasy.totp.verify({
                secret:
                    usuario.mfa_secret,
                encoding: "base32",
                token: codigo,
                window: 1
            });


        // =============================================
        // CÓDIGO INCORRECTO
        // =============================================

        if (!codigoValido) {

            const intentos =
                usuario.intentos_mfa + 1;

            await db.query(
                `UPDATE usuarios
                 SET intentos_mfa = ?
                 WHERE id = ?`,
                [
                    intentos,
                    usuario.id
                ]
            );

            return res.status(401).json({
                mensaje:
                    "Código MFA incorrecto",
                intentos_mfa:
                    intentos,
                intentos_restantes:
                    Math.max(0, 3 - intentos)
            });
        }


        // =============================================
        // CÓDIGO CORRECTO
        // =============================================

        await db.query(
            `UPDATE usuarios
             SET intentos_mfa = 0
             WHERE id = ?`,
            [usuario.id]
        );


        // Generar JWT definitivo
        const token = jwt.sign(
            {
                id: usuario.id,
                email: usuario.email,
                rol: usuario.rol,
                mfa_habilitado: Boolean(usuario.mfa_habilitado)
            },
            process.env.JWT_SECRET,
            {
                expiresIn: "1h"
            }
        );


        return res.status(200).json({
            mensaje:
                "MFA verificado. Inicio de sesión exitoso",

            token,

            usuario: {
                id:
                    usuario.id,

                email:
                    usuario.email,

                nombre_completo:
                    usuario.nombre_completo,

                tienda:
                    usuario.tienda,

                rol:
                    usuario.rol,
                mfa_habilitado:
                    Boolean(usuario.mfa_habilitado)
            }
        });

    } catch (error) {

        console.error(
            "Error verificando MFA:",
            error
        );

        return res.status(500).json({
            mensaje:
                "Error al verificar MFA"
        });
    }
};


// =====================================================
// EXPORTAR FUNCIONES
// =====================================================

module.exports = {
    registrarUsuario,
    loginUsuario,
    configurarMFA,
    activarMFA,
    verificarMFA
};
