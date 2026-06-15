// Server.js
require("dotenv").config();
const app = require("./src/app");

const PORT = Number(process.env.PORT || 4000);

if (!app._started) {
  const server = app.listen(PORT, () => {
    console.log(`🚀 Servidor rodando na porta ${PORT}`);
  });

  server.on("error", (error) => {
    if (error.code === "EADDRINUSE") {
      console.error(`❌ A porta ${PORT} já está em uso.`);
      console.error("Feche o outro processo que está usando essa porta ou rode a API com outra porta.");
      console.error("Windows PowerShell:");
      console.error(`  Get-NetTCPConnection -LocalPort ${PORT} | Select-Object OwningProcess`);
      console.error("  Stop-Process -Id <PID> -Force");
      console.error("Ou rode em outra porta:");
      console.error("  $env:PORT=4001; npm run dev");
      process.exit(1);
    }

    console.error("❌ Erro ao iniciar o servidor:", error);
    process.exit(1);
  });

  app._started = true;
}
