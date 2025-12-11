// src/app.js
require("dotenv").config();
const express = require("express");
const cors = require("cors");

const usuarioRoutes = require("./routes/usuarioRoutes.js");
const errorHandler  = require("./middlewares/errorHandler.js");

const app = express();

console.log("[APP] carregado de:", __filename);

// -------- CORS (antes das rotas) --------
const allowedOrigin = process.env.CORS_ORIGIN || "*";
app.use(
  cors({
    origin: allowedOrigin, // em dev pode ser "*"; ideal: URL do túnel
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
    credentials: false, // true só se usar cookies/sessões
  })
);

app.options("*", cors());

app.use(express.json());

app.get("/health", (_req, res) => {
  console.log("[HEALTH] hit");
  res.status(200).send("ok");
});

app.use("/api/usuarios", usuarioRoutes);

app.get("/", (_req, res) => {
  res.send("🚀 API Savóia rodando!");
});

app.use(errorHandler);

module.exports = app;
