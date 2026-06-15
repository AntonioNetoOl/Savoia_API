// src/middlewares/authMiddleware.js
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret";

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || req.headers.Authorization;

  if (!authHeader || !String(authHeader).startsWith("Bearer ")) {
    return res.status(401).json({ erro: "Token não informado." });
  }

  const token = String(authHeader).replace("Bearer ", "").trim();

  if (!token) {
    return res.status(401).json({ erro: "Token inválido." });
  }

  try {
    const payload = jwt.verify(token, JWT_SECRET);

    // Mantém compatibilidade com possíveis usos antigos de req.usuario
    // e padroniza req.user para as novas rotas.
    req.user = payload;
    req.usuario = payload;

    return next();
  } catch (_error) {
    return res.status(401).json({ erro: "Token inválido ou expirado." });
  }
}

module.exports = authMiddleware;
