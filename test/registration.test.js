const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { before, after, mock, test } = require("node:test");
const { Client } = require("pg");

assert.ok(process.env.SAVOIA_TEST_PGDATA, "Execute npm run test:registration");
assert.equal(process.env.DB_HOST, "127.0.0.1");
assert.equal(process.env.DB_USER, "savoia_test");
assert.notEqual(process.env.DB_PORT, "5432");
mock.method(require("dotenv"), "config", () => ({}));
mock.method(console, "log", () => {});
mock.method(console, "warn", () => {});
let emails = 0;
const transport = {
  async sendMail() { emails += 1; },
};
mock.method(require("nodemailer"), "createTransport", () => transport);
const users = require("../src/controllers/UsuarioController");
const { pool } = require("../src/config/DB");
// Recicla conexões entre empréstimos para expor transações feitas por pool.query.
pool.options.maxUses = 1;
pool.options.statement_timeout = 5000;
const admin = new Client({
  host: process.env.DB_HOST, port: Number(process.env.DB_PORT),
  database: process.env.DB_NAME, user: process.env.DB_USER, password: process.env.DB_PASS,
});

before(async () => {
  await admin.connect();
  const { rows } = await admin.query("SHOW data_directory");
  assert.equal(path.resolve(rows[0].data_directory), path.resolve(process.env.SAVOIA_TEST_PGDATA));
  await admin.query(fs.readFileSync(path.join(__dirname, "fixtures/registration-schema.sql"), "utf8"));
  await admin.query("SET search_path TO public; SET statement_timeout TO 5000");
  await admin.query(fs.readFileSync(path.join(__dirname, "../migrations/202606151_member_core.sql"), "utf8"));
});

after(async () => {
  await pool.end();
  await admin.end();
  mock.restoreAll();
});

async function invoke(handler, body) {
  const res = {
    statusCode: 200,
    status(code) { this.statusCode = code; return this; },
    json(value) { this.body = value; return this; },
  };
  await handler({ body, headers: {} }, res, (error) => { res.error = error; });
  return res;
}

function registration(id) {
  return { nome: "Pessoa Teste", cpf: String(id).padStart(11, "0"), email: `pessoa${id}@example.test`, senha: "senha-ficticia", numero: "0000000000" };
}

async function start(body) {
  const result = await invoke(users.reenviarCodigo, body);
  assert.equal(result.error?.code, undefined);
  assert.equal(result.statusCode, 200);
  const { rows: [verification] } = await admin.query("SELECT codigo FROM verificacoes_email WHERE email=$1 ORDER BY criado_em DESC LIMIT 1", [body.email]);
  return { email: body.email, codigo: verification.codigo };
}

test("falha ao gravar código desfaz a substituição da sessão e não envia e-mail", async () => {
  const emailsBefore = emails;
  await admin.query("INSERT INTO sessoes_cadastro (nome,cpf,email,senha_hash,numero) VALUES ('Antes','00000000001','falha@example.test','hash-ficticio','0000000000')");
  await admin.query(`CREATE FUNCTION reject_test_code() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'Falha de teste' USING ERRCODE = 'P0001'; END $$;
    CREATE TRIGGER reject_test_code BEFORE INSERT ON verificacoes_email
    FOR EACH ROW WHEN (NEW.email = 'falha@example.test') EXECUTE FUNCTION reject_test_code()`);
  const result = await invoke(users.reenviarCodigo, {
    nome: "Pessoa Teste", cpf: "00000000001", email: "falha@example.test", senha: "senha-ficticia", numero: "0000000000",
  });
  assert.equal(result.error?.code, "P0001");
  const sessions = await admin.query("SELECT nome FROM sessoes_cadastro WHERE email='falha@example.test'");
  assert.deepEqual(sessions.rows, [{ nome: "Antes" }]);
  assert.equal((await admin.query("SELECT count(*)::int AS total FROM verificacoes_email WHERE email='falha@example.test'")).rows[0].total, 0);
  assert.equal(emails, emailsBefore);
  assert.equal(pool.totalCount, pool.idleCount);
});

test("cadastro completo confirma conta, código e sessão", async () => {
  const body = registration(3);
  const confirmation = await start(body);
  const result = await invoke(users.confirmarCadastro, confirmation);
  assert.equal(result.error?.code, undefined);
  assert.equal(result.statusCode, 200);
  assert.equal(result.body.message, "Cadastro concluído.");
  assert.equal(result.body.usuario.email_verificado, true);
  assert.equal(result.body.memberLink.reason, "legacy_not_found");
  const saved = await admin.query("SELECT email_verificado FROM usuarios WHERE email=$1", [body.email]);
  assert.deepEqual(saved.rows, [{ email_verificado: true }]);
  assert.equal((await admin.query("SELECT usado FROM verificacoes_email WHERE email=$1", [body.email])).rows[0].usado, true);
  assert.equal((await admin.query("SELECT usado FROM sessoes_cadastro WHERE email=$1", [body.email])).rows[0].usado, true);
  assert.equal(pool.totalCount, pool.idleCount);
});

test("reenvio preserva a sessão de cadastro", async () => {
  const body = registration(4);
  await start(body);
  const session = (await admin.query("SELECT id FROM sessoes_cadastro WHERE email=$1", [body.email])).rows[0].id;
  await admin.query("UPDATE verificacoes_email SET criado_em=NOW()-INTERVAL '1 minute' WHERE email=$1", [body.email]);
  const result = await invoke(users.reenviarCodigo, { email: body.email });
  assert.deepEqual(result.body, { message: "Código enviado" });
  assert.deepEqual((await admin.query("SELECT id FROM sessoes_cadastro WHERE email=$1", [body.email])).rows, [{ id: session }]);
  assert.equal((await admin.query("SELECT count(*)::int AS total FROM verificacoes_email WHERE email=$1", [body.email])).rows[0].total, 2);
});

test("falha de SMTP ocorre após commit e não desfaz sessão ou código", async (t) => {
  const body = registration(5);
  let visibleCodes = 0;
  t.mock.method(transport, "sendMail", async () => {
    visibleCodes = (await admin.query("SELECT count(*)::int AS total FROM verificacoes_email WHERE email=$1", [body.email])).rows[0].total;
    throw new Error("SMTP de teste indisponível");
  });
  const result = await invoke(users.reenviarCodigo, body);
  assert.equal(visibleCodes, 1);
  assert.deepEqual(result.body, { message: "Código gerado (dev / sem SMTP)." });
  assert.equal((await admin.query("SELECT count(*)::int AS total FROM sessoes_cadastro WHERE email=$1", [body.email])).rows[0].total, 1);
});

for (const [id, conflict] of [[6, "email"], [7, "cpf"]]) {
  test(`conflito de ${conflict} retorna 409 sem consumir código ou sessão`, async () => {
    const body = registration(id);
    const confirmation = await start(body);
    await admin.query("INSERT INTO usuarios (nome,cpf,email,senha_hash) VALUES ('Conta existente',$1,$2,'hash-ficticio')", [
      conflict === "cpf" ? body.cpf : "99999999999",
      conflict === "email" ? body.email : "existing@example.test",
    ]);
    if (conflict === "email") {
      await admin.query(`CREATE FUNCTION conflict_test_effect() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN UPDATE sessoes_cadastro SET usado=true WHERE email=NEW.email; RETURN NEW; END $$;
        CREATE TRIGGER conflict_test_effect BEFORE INSERT ON usuarios
        FOR EACH ROW WHEN (NEW.email = 'pessoa6@example.test') EXECUTE FUNCTION conflict_test_effect()`);
    }
    const result = await invoke(users.confirmarCadastro, confirmation);
    assert.equal(result.statusCode, 409);
    assert.deepEqual(result.body, { erro: "Usuário já existe." });
    assert.equal((await admin.query("SELECT usado FROM verificacoes_email WHERE email=$1", [body.email])).rows[0].usado, false);
    assert.equal((await admin.query("SELECT usado FROM sessoes_cadastro WHERE email=$1", [body.email])).rows[0].usado, false);
    assert.equal(pool.totalCount, pool.idleCount);
  });
}

test("envios concorrentes não misturam commit e rollback", async () => {
  await admin.query(`CREATE FUNCTION parallel_test_code() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN
      PERFORM pg_sleep(0.1);
      IF NEW.email = 'pessoa9@example.test' THEN RAISE EXCEPTION 'Falha de teste' USING ERRCODE = 'P0003'; END IF;
      RETURN NEW;
    END $$;
    CREATE TRIGGER parallel_test_code BEFORE INSERT ON verificacoes_email
    FOR EACH ROW WHEN (NEW.email IN ('pessoa8@example.test','pessoa9@example.test')) EXECUTE FUNCTION parallel_test_code()`);
  const [success, failure] = await Promise.all([
    invoke(users.reenviarCodigo, registration(8)),
    invoke(users.reenviarCodigo, registration(9)),
  ]);
  assert.deepEqual(success.body, { message: "Código enviado" });
  assert.equal(failure.error?.code, "P0003");
  for (const table of ["sessoes_cadastro", "verificacoes_email"]) {
    const saved = await admin.query(`SELECT email::text FROM ${table} WHERE email IN ('pessoa8@example.test','pessoa9@example.test')`);
    assert.deepEqual(saved.rows, [{ email: "pessoa8@example.test" }]);
  }
  assert.equal(pool.totalCount, pool.idleCount);
});

test("confirmações concorrentes preservam as duas contas e liberam conexões", async () => {
  const confirmations = await Promise.all([start(registration(10)), start(registration(11))]);
  const results = await Promise.all(confirmations.map((body) => invoke(users.confirmarCadastro, body)));
  assert.deepEqual(results.map((res) => res.statusCode), [200, 200]);
  assert.ok(results.every((res) => res.body?.message === "Cadastro concluído."));
  const saved = await admin.query("SELECT email::text FROM usuarios WHERE email IN ('pessoa10@example.test','pessoa11@example.test') ORDER BY email");
  assert.deepEqual(saved.rows, [{ email: "pessoa10@example.test" }, { email: "pessoa11@example.test" }]);
  assert.equal(pool.totalCount, pool.idleCount);
});

test("falha do vínculo legado preserva o cadastro já confirmado", async () => {
  const confirmation = await start(registration(12));
  await admin.query("ALTER TABLE socios_legado RENAME TO test_unavailable_legacy");
  try {
    const result = await invoke(users.confirmarCadastro, confirmation);
    assert.equal(result.statusCode, 200);
    assert.equal(result.body.memberLink.reason, "legacy_link_error");
    assert.equal((await admin.query("SELECT email_verificado FROM usuarios WHERE email=$1", [confirmation.email])).rows[0].email_verificado, true);
    assert.equal((await admin.query("SELECT usado FROM verificacoes_email WHERE email=$1", [confirmation.email])).rows[0].usado, true);
    assert.equal(pool.totalCount, pool.idleCount);
  } finally {
    await admin.query("ALTER TABLE test_unavailable_legacy RENAME TO socios_legado");
  }
});

test("falha na confirmação desfaz usuário e consumo do código", async () => {
  const email = "confirm-failure@example.test";
  const sent = await invoke(users.reenviarCodigo, {
    nome: "Pessoa Teste", cpf: "00000000002", email, senha: "senha-ficticia", numero: "0000000000",
  });
  assert.equal(sent.error, undefined);
  const { rows: [verification] } = await admin.query("SELECT codigo FROM verificacoes_email WHERE email=$1", [email]);
  await admin.query(`CREATE FUNCTION reject_test_session() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN RAISE EXCEPTION 'Falha de teste' USING ERRCODE = 'P0002'; END $$;
    CREATE TRIGGER reject_test_session BEFORE UPDATE ON sessoes_cadastro
    FOR EACH ROW WHEN (NEW.email = 'confirm-failure@example.test' AND NEW.usado) EXECUTE FUNCTION reject_test_session()`);
  const result = await invoke(users.confirmarCadastro, { email, codigo: verification.codigo });
  assert.equal(result.error?.code, "P0002");
  assert.equal((await admin.query("SELECT count(*)::int AS total FROM usuarios WHERE email=$1", [email])).rows[0].total, 0);
  assert.equal((await admin.query("SELECT usado FROM verificacoes_email WHERE email=$1", [email])).rows[0].usado, false);
  assert.equal((await admin.query("SELECT usado FROM sessoes_cadastro WHERE email=$1", [email])).rows[0].usado, false);
  assert.equal(pool.totalCount, pool.idleCount);
});
