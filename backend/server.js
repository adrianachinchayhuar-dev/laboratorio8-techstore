const express = require("express");
const cors = require("cors");
require("dotenv").config();

const db = require("./src/config/database");
const authRoutes = require("./src/routes/authRoutes");

const protectedRoutes =
    require("./src/routes/protectedRoutes");

const app = express();

app.use(cors());
app.use(express.json());

app.use("/api/auth", authRoutes);
app.use("/api", protectedRoutes);


app.get("/", (req, res) => {
    res.json({
        mensaje: "API TechStore funcionando correctamente"
    });
});

// Prueba de conexión con MySQL
app.get("/api/test-db", async (req, res) => {
    try {
        const [resultado] = await db.query(
            "SELECT NOW() AS fecha_servidor"
        );

        res.json({
            mensaje: "Conexión con MySQL exitosa",
            database: "techstore",
            fecha: resultado[0].fecha_servidor
        });

    } catch (error) {
        console.error(error);

        res.status(500).json({
            mensaje: "Error al conectar con MySQL",
            error: error.message
        });
    }
});

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(
        `Servidor TechStore ejecutándose en http://localhost:${PORT}`
    );
});