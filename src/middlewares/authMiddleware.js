const jwt = require("jsonwebtoken");

function autenticarToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // formato: Bearer <token>

  if (!token) {
    return res.status(401).json({ erro: "Acesso negado. Token ausente." });
  }

  try {
    const usuario = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = usuario; 
    next(); 
  } catch (err) {
    return res.status(403).json({ erro: "Token inválido ou expirado." });
  }
}

module.exports = autenticarToken;
