// Server.js
require("dotenv").config();
const app = require("./src/app");

const PORT = process.env.PORT || 4000;

if (!app._started) {
  app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
  });
  app._started = true;
}
