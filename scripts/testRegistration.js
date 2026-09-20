const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const net = require("node:net");
const { randomBytes } = require("node:crypto");
const { execFileSync, spawnSync } = require("node:child_process");

const pgBin = process.argv[2] || "C:/Program Files/PostgreSQL/18/bin";
const root = fs.mkdtempSync(path.join(os.tmpdir(), "savoia-registration-"));
const data = path.join(root, "data");
const passwordFile = path.join(root, "password");
const password = randomBytes(32).toString("hex");
const executable = (name) => path.join(pgBin, name + (process.platform === "win32" ? ".exe" : ""));
const run = (name, args) => execFileSync(executable(name), args, { windowsHide: true, stdio: "ignore", timeout: 30000 });

async function main() {
  try {
    const server = net.createServer();
    await new Promise((resolve, reject) => {
      server.once("error", reject);
      server.listen(0, "127.0.0.1", resolve);
    });
    const port = server.address().port;
    await new Promise((resolve) => server.close(resolve));
    fs.writeFileSync(passwordFile, password, { mode: 0o600 });
    run("initdb", ["-D", data, "-U", "savoia_test", "--auth=scram-sha-256", "--pwfile", passwordFile, "--encoding=UTF8", "--locale=C"]);
    fs.unlinkSync(passwordFile);
    run("pg_ctl", ["-D", data, "-l", path.join(root, "postgres.log"), "-o", `-h 127.0.0.1 -p ${port}`, "-w", "start"]);
    console.log(`PostgreSQL descartável: 127.0.0.1:${port}; diretório ${data}`);

    const result = spawnSync(process.execPath, ["--test", "test/registration.test.js"], {
      cwd: path.resolve(__dirname, ".."), windowsHide: true, stdio: "inherit", timeout: 60000,
      env: {
        ...process.env,
        SAVOIA_TEST_PGDATA: data,
        DB_HOST: "127.0.0.1", DB_PORT: String(port), DB_NAME: "postgres",
        DB_USER: "savoia_test", DB_PASS: password,
        JWT_SECRET: randomBytes(32).toString("hex"),
        SMTP_HOST: "smtp.invalid", SMTP_PORT: "1025", SMTP_USER: "test", SMTP_PASS: password,
      },
    });
    process.exitCode = result.status ?? 1;
  } catch (error) {
    console.error("Não foi possível preparar os testes PostgreSQL:", error.code || error.status || error.name);
    process.exitCode = 1;
  } finally {
    try {
      if (fs.existsSync(path.join(data, "postmaster.pid"))) {
        run("pg_ctl", ["-D", data, "-m", "immediate", "-w", "stop"]);
      }
      const resolved = path.resolve(root);
      if (path.dirname(resolved) !== path.resolve(os.tmpdir()) || !path.basename(resolved).startsWith("savoia-registration-")) {
        throw new Error("Diretório temporário inesperado");
      }
      fs.rmSync(resolved, { recursive: true, force: true });
    } catch {
      console.error(`Limpeza não concluída; instância de teste em ${data}`);
      process.exitCode = 1;
    }
  }
}

main();
