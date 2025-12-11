// src/middlewares/errorHandler.js
module.exports = (err, _req, res, _next) => {
  console.error('🚨 ERRO NO SERVIDOR');
  console.error(err.stack || err);

  const status = err.status || 500;
  const message = err.message || 'Erro interno do servidor.';

  res.status(status).json({
    erro: message,
    detalhe: err.detail || null,
    code: err.code || null,
  });
};
